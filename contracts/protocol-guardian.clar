;; Ethereal Flow Protocol - Protocol Guardian Contract
;; Manages hierarchical access structures and device authorization within the flow ecosystem
;; Enforces role-based governance with fine-grained permission tracking and device lifecycle management

;; === Error Constants ===
(define-constant FAIL-PERMISSION-DENIED (err u1000))
(define-constant FAIL-RESOURCE-DUPLICATE (err u1001))
(define-constant FAIL-ROLE-INVALID (err u1002))
(define-constant FAIL-RESOURCE-NOT-FOUND (err u1003))
(define-constant FAIL-NOT-CUSTODIAN (err u1004))
(define-constant FAIL-CANNOT-REVOKE-SELF (err u1005))
(define-constant FAIL-DEVICE-INACTIVE (err u1006))
(define-constant FAIL-DEVICE-UNREGISTERED (err u1007))
(define-constant FAIL-UNKNOWN-PRINCIPAL (err u1008))

;; === Role Definitions ===
(define-constant LEVEL-ADMIN u100)
(define-constant LEVEL-CONTRIBUTOR u200)
(define-constant LEVEL-OBSERVER u300)

;; === Data Structures ===

;; Resource custodianship registry
(define-map resource-custodians 
  { resource-id: (string-utf8 36) }
  { custodian: principal }
)

;; Fine-grained role assignments per resource
(define-map resource-roles
  { resource-id: (string-utf8 36), principal: principal }
  { level: uint }
)

;; Device registration and lifecycle tracking
(define-map device-registry
  { principal: principal, device-id: (string-utf8 36) }
  { active-status: bool, label: (string-utf8 64), last-activity: uint }
)

;; Enumeration support for multi-device users
(define-map device-enumeration
  { principal: principal }
  { device-ids: (list 20 (string-utf8 36)) }
)

;; === Private Utilities ===

;; Verify role definition validity
(define-private (role-is-valid (level uint))
  (or
    (is-eq level LEVEL-ADMIN)
    (is-eq level LEVEL-CONTRIBUTOR)
    (is-eq level LEVEL-OBSERVER)
  )
)

;; Determine role-based access sufficiency
(define-private (role-permits-action (principal-addr principal) (resource-id (string-utf8 36)) (min-level uint))
  (let (
    (current-level (unwrap-panic (retrieve-principal-role principal-addr resource-id)))
  )
    (>= min-level current-level)
  )
)

;; === Read-Only Functions ===

;; Fetch resource custodian information
(define-read-only (retrieve-custodian (resource-id (string-utf8 36)))
  (map-get? resource-custodians { resource-id: resource-id })
)

;; Verify custodianship relationship
(define-read-only (validate-custodian (principal-addr principal) (resource-id (string-utf8 36)))
  (let (
    (custodian-entry (map-get? resource-custodians { resource-id: resource-id }))
  )
    (if (is-some custodian-entry)
      (is-eq principal-addr (get custodian (unwrap-panic custodian-entry)))
      false
    )
  )
)

;; Retrieve principal's role assignment
(define-read-only (retrieve-principal-role (principal-addr principal) (resource-id (string-utf8 36)))
  (let (
    (role-entry (map-get? resource-roles { resource-id: resource-id, principal: principal-addr }))
  )
    (if (is-some role-entry)
      (ok (get level (unwrap-panic role-entry)))
      (ok u0)
    )
  )
)

;; Query device activation status
(define-read-only (check-device-active (principal-addr principal) (device-id (string-utf8 36)))
  (match (map-get? device-registry { principal: principal-addr, device-id: device-id })
    device-rec (get active-status device-rec)
    false
  )
)

;; Enumerate registered devices for principal
(define-read-only (fetch-device-list (principal-addr principal))
  (match (map-get? device-enumeration { principal: principal-addr })
    enum-data (ok (get device-ids enum-data))
    (ok (list))
  )
)

;; === Public Transactions ===

;; Establish resource with caller as custodian
(define-public (establish-resource (resource-id (string-utf8 36)))
  (let (
    (custodian-entry (map-get? resource-custodians { resource-id: resource-id }))
  )
    (if (is-some custodian-entry)
      FAIL-RESOURCE-DUPLICATE
      (begin
        (map-set resource-custodians
          { resource-id: resource-id }
          { custodian: tx-sender }
        )
        
        (map-set resource-roles 
          { resource-id: resource-id, principal: tx-sender }
          { level: LEVEL-ADMIN }
        )
        
        (ok true)
      )
    )
  )
)

;; Withdraw principal's resource access
(define-public (withdraw-access (resource-id (string-utf8 36)) (principal-addr principal))
  (if (not (validate-custodian tx-sender resource-id))
    FAIL-NOT-CUSTODIAN
    
    (if (validate-custodian principal-addr resource-id)
      FAIL-CANNOT-REVOKE-SELF
      
      (begin
        (map-delete resource-roles
          { resource-id: resource-id, principal: principal-addr }
        )
        (ok true)
      )
    )
  )
)

;; Deactivate device from user's registry
(define-public (deactivate-device (device-id (string-utf8 36)))
  (let (
    (device-entry (map-get? device-registry { principal: tx-sender, device-id: device-id }))
  )
    (if (is-none device-entry)
      FAIL-DEVICE-UNREGISTERED
      (begin
        (map-set device-registry
          { principal: tx-sender, device-id: device-id }
          { active-status: false, 
            label: (get label (unwrap-panic device-entry)), 
            last-activity: (unwrap-panic (get-block-info? time (- block-height u1))) }
        )
        (ok true)
      )
    )
  )
)

;; Record device activity checkpoint
(define-public (checkpoint-device-activity (device-id (string-utf8 36)))
  (let (
    (device-entry (map-get? device-registry { principal: tx-sender, device-id: device-id }))
  )
    (if (is-none device-entry)
      FAIL-DEVICE-UNREGISTERED
      (let (
        (device-info (unwrap-panic device-entry))
      )
        (if (not (get active-status device-info))
          FAIL-DEVICE-INACTIVE
          (begin
            (map-set device-registry
              { principal: tx-sender, device-id: device-id }
              { active-status: true,
                label: (get label device-info),
                last-activity: (unwrap-panic (get-block-info? time (- block-height u1))) }
            )
            (ok true)
          )
        )
      )
    )
  )
)

;; Reassign resource custodianship
(define-public (reassign-custodian (resource-id (string-utf8 36)) (new-custodian principal))
  (if (not (validate-custodian tx-sender resource-id))
    FAIL-NOT-CUSTODIAN
    
    (begin
      (map-set resource-custodians
        { resource-id: resource-id }
        { custodian: new-custodian }
      )
      
      (map-delete resource-roles
        { resource-id: resource-id, principal: tx-sender }
      )
      
      (map-set resource-roles
        { resource-id: resource-id, principal: new-custodian }
        { level: LEVEL-ADMIN }
      )
      
      (ok true)
    )
  )
)