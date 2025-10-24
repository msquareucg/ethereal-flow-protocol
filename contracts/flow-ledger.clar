;; Ethereal Flow Protocol - Flow Ledger Contract
;; Core ledger management system for distributed data references and synchronization primitives
;; Enables users to maintain cryptographic anchors for off-chain data while preserving privacy

;; === Error Definitions ===
(define-constant FAIL-UNAUTHORIZED (err u100))
(define-constant FAIL-ENTRY-NOT-FOUND (err u101))
(define-constant FAIL-MALFORMED-INPUT (err u102))
(define-constant FAIL-ENTRY-DUPLICATE (err u103))
(define-constant FAIL-INVALID-PRINCIPAL (err u104))

;; === Constants ===
(define-constant MAX-ENTRY-COUNT u100)

;; === Data Maps ===

;; Primary ledger storing flow entries indexed by reference identifier
(define-map flow-entries
  { entry-id: (string-utf8 128) }
  {
    custodian: principal,
    content-hash: (buff 32),
    recorded-height: uint,
    version-tag: (string-utf8 32),
    annotations: (optional (string-utf8 256))
  }
)

;; Maintains per-user entry inventory for efficient enumeration
(define-map user-entry-inventory 
  { user: principal }
  { entry-ids: (list 100 (string-utf8 128)) }
)

;; Tracks delegated access permissions between principals
(define-map delegation-grants
  { entry-id: (string-utf8 128), delegated-to: principal }
  { write-permission: bool }
)

;; === Private Helpers ===

;; Evaluates whether a principal possesses write authority over an entry
(define-private (evaluate-write-permission (entry-id (string-utf8 128)) (principal-addr principal))
  (let (
    (flow-record (map-get? flow-entries { entry-id: entry-id }))
  )
    (if (is-some flow-record)
      (or
        (is-eq (get custodian (unwrap! flow-record false)) principal-addr)
        (default-to false (get write-permission (map-get? delegation-grants { entry-id: entry-id, delegated-to: principal-addr })))
      )
      false
    )
  )
)

;; Appends an entry identifier to the user's inventory collection
(define-private (append-entry-to-inventory (user principal) (entry-id (string-utf8 128)))
  (let (
    (existing-inventory (default-to { entry-ids: (list) } (map-get? user-entry-inventory { user: user })))
    (expanded-list (unwrap! (as-max-len? (append (get entry-ids existing-inventory) entry-id) MAX-ENTRY-COUNT) false))
  )
    (map-set user-entry-inventory { user: user } { entry-ids: expanded-list })
    true
  )
)

;; === Read-Only Interface ===

;; Retrieve complete entry record by identifier
(define-read-only (fetch-flow-entry (entry-id (string-utf8 128)))
  (match (map-get? flow-entries { entry-id: entry-id })
    entry-record (ok entry-record)
    FAIL-ENTRY-NOT-FOUND
  )
)

;; Determine if principal has access to specified entry
(define-read-only (query-access-permission (entry-id (string-utf8 128)) (principal-addr principal))
  (let (
    (entry-record (map-get? flow-entries { entry-id: entry-id }))
  )
    (if (is-some entry-record)
      (ok (or
        (is-eq (get custodian (unwrap-panic entry-record)) principal-addr)
        (is-some (map-get? delegation-grants { entry-id: entry-id, delegated-to: principal-addr }))
      ))
      FAIL-ENTRY-NOT-FOUND
    )
  )
)

;; Enumerate all entry identifiers for a user
(define-read-only (retrieve-user-entries (user principal))
  (ok (get entry-ids (default-to { entry-ids: (list) } (map-get? user-entry-inventory { user: user }))))
)

;; === Public Transactions ===

;; Register new entry with cryptographic anchor and versioning
(define-public (register-entry 
    (entry-id (string-utf8 128)) 
    (content-hash (buff 32)) 
    (version-tag (string-utf8 32)) 
    (annotations (optional (string-utf8 256))))
  (let (
    (initiator tx-sender)
    (existing-entry (map-get? flow-entries { entry-id: entry-id }))
  )
    (asserts! (is-none existing-entry) FAIL-ENTRY-DUPLICATE)
    
    (map-set flow-entries
      { entry-id: entry-id }
      {
        custodian: initiator,
        content-hash: content-hash,
        recorded-height: block-height,
        version-tag: version-tag,
        annotations: annotations
      }
    )
    
    (asserts! (append-entry-to-inventory initiator entry-id) FAIL-MALFORMED-INPUT)
    
    (ok true)
  )
)

;; Modify existing entry with authorization verification
(define-public (modify-entry 
    (entry-id (string-utf8 128)) 
    (content-hash (buff 32)) 
    (version-tag (string-utf8 32)) 
    (annotations (optional (string-utf8 256))))
  (let (
    (initiator tx-sender)
    (entry-record (map-get? flow-entries { entry-id: entry-id }))
  )
    (asserts! (is-some entry-record) FAIL-ENTRY-NOT-FOUND)
    (asserts! (evaluate-write-permission entry-id initiator) FAIL-UNAUTHORIZED)
    
    (map-set flow-entries
      { entry-id: entry-id }
      {
        custodian: (get custodian (unwrap-panic entry-record)),
        content-hash: content-hash,
        recorded-height: block-height,
        version-tag: version-tag,
        annotations: annotations
      }
    )
    
    (ok true)
  )
)

;; Grant delegation access to another principal
(define-public (grant-delegation (entry-id (string-utf8 128)) (principal-addr principal) (write-permission bool))
  (let (
    (initiator tx-sender)
    (entry-record (map-get? flow-entries { entry-id: entry-id }))
  )
    (asserts! (is-some entry-record) FAIL-ENTRY-NOT-FOUND)
    (asserts! (is-eq (get custodian (unwrap-panic entry-record)) initiator) FAIL-UNAUTHORIZED)
    (asserts! (not (is-eq principal-addr initiator)) FAIL-INVALID-PRINCIPAL)
    
    (map-set delegation-grants
      { entry-id: entry-id, delegated-to: principal-addr }
      { write-permission: write-permission }
    )
    
    (ok true)
  )
)

;; Revoke delegation access for a principal
(define-public (revoke-delegation (entry-id (string-utf8 128)) (principal-addr principal))
  (let (
    (initiator tx-sender)
    (entry-record (map-get? flow-entries { entry-id: entry-id }))
  )
    (asserts! (is-some entry-record) FAIL-ENTRY-NOT-FOUND)
    (asserts! (is-eq (get custodian (unwrap-panic entry-record)) initiator) FAIL-UNAUTHORIZED)
    
    (map-delete delegation-grants { entry-id: entry-id, delegated-to: principal-addr })
    
    (ok true)
  )
)