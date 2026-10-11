// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title WAFRegistry (v2)
 * @notice Consortium registry for cross-domain Wi-Fi roaming trust.
 *
 * DESIGN INVARIANT (privacy): no device or user identifier is stored. A
 * credential is referenced only by
 *
 *      tag = keccak256(abi.encodePacked(issuer, cid))
 *
 * where `cid` is a 256-bit nonce generated at issuance, held inside the
 * supplicant's EAP-TLS credential, and never transmitted in the clear. Binding
 * the issuer into the tag makes the namespace issuer-scoped, so one member
 * cannot squat another member's tags by front-running issuance.
 *
 * Note honestly what IS observable on-chain: per credential, the issuing
 * member, the issuance block timestamp, the expiry, the assurance level, and
 * the revocation timestamp if revoked. The ledger does not reveal who or what
 * device a credential belongs to, nor where or when it was used, but it is not
 * metadata-free and the paper must not claim that it is.
 *
 * DESIGN INVARIANT (layering): this contract is an AUTHORISATION ORACLE, not an
 * authentication channel. Authentication is unmodified 802.1X/EAP-TLS; the PMK
 * is the first 256 BITS of the EAP MSK (RFC 5247 Sec 1.2); the 802.11i four-way
 * handshake is untouched.
 *
 * GOVERNANCE: permissioned proof-of-authority, m-of-n over admin keys. No
 * token, no stake, no slashing; no economic-security claim is made.
 *
 * KNOWN AVAILABILITY COUPLING: ejecting a member invalidates every credential
 * it issued, including for devices currently roaming elsewhere. This is
 * deliberate and is discussed in the paper's limitations.
 */
contract WAFRegistry {
    // ---------------------------------------------------------------- types

    struct Member {
        bytes32 rcoi;
        uint64  joinedAt;
        uint64  expiresAt;
        bool    active;
    }

    struct Credential {
        address issuer;
        uint64  notAfter;   // MUST be non-zero; lifetime is capped on-chain
        uint64  epoch;      // bitmap namespace this credential's slot lives in
        uint32  slot;       // index within (issuer, epoch) bitmap
        uint8   loa;
        bool    revoked;
        uint64  revokedAt;
    }

    // ------------------------------------------------------------- storage

    mapping(address => bool) public isAdmin;
    uint16 public adminCount;
    uint8  public quorum;

    mapping(address => Member)     public members;
    mapping(bytes32 => Credential) public credentials;

    /// Bulk revocation A: bitmap, namespaced per (issuer, epoch). A member can
    /// only ever write into its OWN namespace, so bitmap revocation cannot be
    /// used to grief another member's credentials.
    mapping(address => mapping(uint64 => mapping(uint256 => uint256))) public revocationBitmap;

    /// Bulk revocation B: per-(issuer, epoch) Merkle root over the revoked set.
    /// Advisory to the authentication server, which checks non-membership
    /// off-chain; `check()` cannot evaluate a Merkle proof cheaply, so this
    /// path is reported as advisory rather than enforced on-chain.
    mapping(address => mapping(uint64 => bytes32)) public revocationRoot;

    /// Next free bitmap slot per (issuer, epoch).
    mapping(address => mapping(uint64 => uint32)) public nextSlot;

    /// Current epoch per issuer. Credentials are issued into it.
    mapping(address => uint64) public issuerEpoch;

    /// Maximum credential lifetime. Bounds exposure when revocation is delayed
    /// or a replica is partitioned: a stale replica fails to expiry, never to
    /// indefinite admission.
    uint64 public constant MAX_CREDENTIAL_LIFETIME = 7 days;

    /// Governance proposals. `proposalEpoch` invalidates all per-admin
    /// approval bits for an action once it executes, so a quorum must be
    /// re-gathered every time — this closes the approval-replay flaw in which
    /// m-of-n silently degrades to 1-of-n after the first execution.
    mapping(bytes32 => uint64) public proposalEpoch;
    mapping(bytes32 => uint8)  public approvalCount;
    mapping(bytes32 => mapping(uint64 => mapping(address => bool))) private approved;

    // -------------------------------------------------------------- events

    event AdminAdded(address indexed admin);
    event AdminRemoved(address indexed admin);
    event QuorumChanged(uint8 quorum);
    event MemberAdmitted(address indexed ap, bytes32 indexed rcoi, uint64 expiresAt);
    event MemberRemoved(address indexed ap);
    event CredentialIssued(bytes32 indexed tag, address indexed issuer,
                           uint64 notAfter, uint64 epoch, uint32 slot, uint8 loa);
    event CredentialRevoked(bytes32 indexed tag, address indexed by, uint64 at);
    event BitmapRevoked(address indexed issuer, uint64 indexed epoch, uint256 word, uint256 bits);
    event RevocationRootPublished(address indexed issuer, uint64 indexed epoch, bytes32 root);
    event EpochRolled(address indexed issuer, uint64 newEpoch);

    // ------------------------------------------------------------- errors

    error NotAdmin();
    error NotActiveMember();
    error AlreadyExists();
    error UnknownCredential();
    error UnknownMember();
    error NotIssuer();
    error BadQuorum();
    error BadLifetime();
    error SlotOverflow();

    // --------------------------------------------------------- constructor

    constructor(address[] memory initialAdmins, uint8 quorum_) {
        for (uint256 i = 0; i < initialAdmins.length; ++i) {
            if (!isAdmin[initialAdmins[i]]) {
                isAdmin[initialAdmins[i]] = true;
                ++adminCount;
                emit AdminAdded(initialAdmins[i]);
            }
        }
        // Validate against the DE-DUPLICATED count, not the array length:
        // ([A,A,A], 3) would otherwise deploy an unreachable quorum.
        if (quorum_ == 0 || quorum_ > adminCount) revert BadQuorum();
        quorum = quorum_;
        emit QuorumChanged(quorum_);
    }

    // ------------------------------------------------------------ modifiers

    modifier onlyAdmin() {
        if (!isAdmin[msg.sender]) revert NotAdmin();
        _;
    }

    modifier onlyActiveMember() {
        if (!_memberActive(msg.sender)) revert NotActiveMember();
        _;
    }

    function _memberActive(address ap) private view returns (bool) {
        Member storage m = members[ap];
        if (!m.active) return false;
        if (m.expiresAt != 0 && m.expiresAt < block.timestamp) return false;
        return true;
    }

    // ----------------------------------------------------------- governance

    /// Returns true when THIS call satisfied the quorum and the action ran.
    /// On execution the proposal's epoch is bumped, invalidating every prior
    /// approval bit, so the next identical proposal starts from zero.
    function _approve(bytes32 action) private returns (bool) {
        uint64 e = proposalEpoch[action];
        if (!approved[action][e][msg.sender]) {
            approved[action][e][msg.sender] = true;
            ++approvalCount[action];
        }
        if (approvalCount[action] < quorum) return false;
        proposalEpoch[action] = e + 1;
        approvalCount[action] = 0;
        return true;
    }

    function admitMember(address ap, bytes32 rcoi, uint64 expiresAt)
        external onlyAdmin returns (bool)
    {
        if (members[ap].active) revert AlreadyExists();
        if (!_approve(keccak256(abi.encode("admit", ap, rcoi, expiresAt)))) return false;
        members[ap] = Member(rcoi, uint64(block.timestamp), expiresAt, true);
        emit MemberAdmitted(ap, rcoi, expiresAt);
        return true;
    }

    function removeMember(address ap) external onlyAdmin returns (bool) {
        if (members[ap].joinedAt == 0) revert UnknownMember();
        if (!_approve(keccak256(abi.encode("remove", ap)))) return false;
        members[ap].active = false;
        emit MemberRemoved(ap);
        return true;
    }

    /// Admin key rotation. Without this, a lost or compromised admin key
    /// permanently degrades or bricks governance.
    function addAdmin(address a) external onlyAdmin returns (bool) {
        if (isAdmin[a]) revert AlreadyExists();
        if (!_approve(keccak256(abi.encode("addAdmin", a)))) return false;
        isAdmin[a] = true; ++adminCount;
        emit AdminAdded(a);
        return true;
    }

    function removeAdmin(address a) external onlyAdmin returns (bool) {
        if (!isAdmin[a]) revert NotAdmin();
        if (adminCount - 1 < quorum) revert BadQuorum();
        if (!_approve(keccak256(abi.encode("removeAdmin", a)))) return false;
        isAdmin[a] = false; --adminCount;
        emit AdminRemoved(a);
        return true;
    }

    function setQuorum(uint8 q) external onlyAdmin returns (bool) {
        if (q == 0 || q > adminCount) revert BadQuorum();
        if (!_approve(keccak256(abi.encode("setQuorum", q)))) return false;
        quorum = q;
        emit QuorumChanged(q);
        return true;
    }

    // ----------------------------------------------------------- issuance

    /// Deterministic, issuer-scoped tag. `hcid` is keccak256(cid); the raw
    /// nonce never leaves the credential. The authentication server recomputes
    /// this from the certificate's issuer and the proven cid.
    function tagFor(address issuer, bytes32 hcid) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(issuer, hcid));
    }

    /// The tag is DERIVED FROM msg.sender on-chain, never supplied by the
    /// caller. A member therefore cannot occupy a slot in another member's tag
    /// namespace, which closes front-running of pending issuance.
    function _issue(bytes32 hcid, uint64 notAfter, uint8 loa) private {
        bytes32 tag = tagFor(msg.sender, hcid);
        if (credentials[tag].issuer != address(0)) revert AlreadyExists();
        if (notAfter <= block.timestamp ||
            notAfter > block.timestamp + MAX_CREDENTIAL_LIFETIME) revert BadLifetime();

        uint64 e = issuerEpoch[msg.sender];
        uint32 s = nextSlot[msg.sender][e];
        if (s == type(uint32).max) revert SlotOverflow();
        nextSlot[msg.sender][e] = s + 1;

        credentials[tag] = Credential({
            issuer: msg.sender, notAfter: notAfter, epoch: e,
            slot: s, loa: loa, revoked: false, revokedAt: 0
        });
        emit CredentialIssued(tag, msg.sender, notAfter, e, s, loa);
    }

    function issueCredential(bytes32 hcid, uint64 notAfter, uint8 loa)
        external onlyActiveMember { _issue(hcid, notAfter, loa); }

    function issueBatch(bytes32[] calldata hcids, uint64 notAfter, uint8 loa)
        external onlyActiveMember
    {
        for (uint256 i = 0; i < hcids.length; ++i) _issue(hcids[i], notAfter, loa);
    }

    /// Roll to a fresh bitmap namespace. Credentials issued in prior epochs
    /// keep their own epoch's bitmap, so rolling never un-revokes anything.
    function rollEpoch() external onlyActiveMember {
        uint64 e = issuerEpoch[msg.sender] + 1;
        issuerEpoch[msg.sender] = e;
        emit EpochRolled(msg.sender, e);
    }

    // ---------------------------------------------------------- revocation

    /// Path 1: per-credential. Issuer or any admin.
    /// (Admins are deliberately permitted without quorum so that a single
    /// compromised device can be dealt with immediately; the asymmetry with
    /// member admission is intentional and is discussed in the paper.)
    function revoke(bytes32 tag) public {
        Credential storage c = credentials[tag];
        if (c.issuer == address(0)) revert UnknownCredential();
        if (c.issuer != msg.sender && !isAdmin[msg.sender]) revert NotIssuer();
        c.revoked = true;
        c.revokedAt = uint64(block.timestamp);
        emit CredentialRevoked(tag, msg.sender, c.revokedAt);
    }

    function revokeBatch(bytes32[] calldata tags) external {
        for (uint256 i = 0; i < tags.length; ++i) revoke(tags[i]);
    }

    /// Path 2: bitmap, confined to the caller's own (issuer, epoch) namespace.
    function revokeBitmap(uint64 epoch, uint256 word, uint256 bits) public onlyActiveMember {
        revocationBitmap[msg.sender][epoch][word] |= bits;
        emit BitmapRevoked(msg.sender, epoch, word, bits);
    }

    /// Scattered-case bitmap revocation: several words in one transaction.
    function revokeBitmapBatch(uint64 epoch, uint256[] calldata words, uint256[] calldata bits)
        external onlyActiveMember
    {
        for (uint256 i = 0; i < words.length; ++i) {
            revocationBitmap[msg.sender][epoch][words[i]] |= bits[i];
            emit BitmapRevoked(msg.sender, epoch, words[i], bits[i]);
        }
    }

    function isBitmapRevoked(address issuer, uint64 epoch, uint32 slot)
        public view returns (bool)
    {
        return (revocationBitmap[issuer][epoch][slot >> 8] >> (slot & 0xff)) & 1 == 1;
    }

    /// Path 3: Merkle root. Advisory — see the storage comment.
    function publishRevocationRoot(uint64 epoch, bytes32 root) external onlyActiveMember {
        revocationRoot[msg.sender][epoch] = root;
        emit RevocationRootPublished(msg.sender, epoch, root);
    }

    // ------------------------------------------------------------- queries

    /// The hot path: executed as a local `eth_call` against the replica the
    /// access point already holds. No gas, no consensus round, no network hop.
    /// Consults BOTH the per-credential flag and the bitmap, so the cheap bulk
    /// path is actually enforced rather than merely recorded.
    function check(bytes32 tag)
        external view returns (bool valid, uint8 loa, address issuer)
    {
        Credential storage c = credentials[tag];
        if (c.issuer == address(0)) return (false, 0, address(0));
        if (c.revoked) return (false, c.loa, c.issuer);
        if (c.notAfter < block.timestamp) return (false, c.loa, c.issuer);
        if (isBitmapRevoked(c.issuer, c.epoch, c.slot)) return (false, c.loa, c.issuer);
        if (!_memberActive(c.issuer)) return (false, c.loa, c.issuer);
        return (true, c.loa, c.issuer);
    }

    function memberRcoi(address ap) external view returns (bytes32) {
        return members[ap].rcoi;
    }
}
