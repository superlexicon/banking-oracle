# `banking-oracle` — Multi-Entity, Multi-Bank & Payment Acquiring Oracle

Standalone, dependency-isolated Rust service connecting corporate commercial banking rails and merchant payment acquirers to SuperLexicon Haltproof Subroutines (`AssetLedger`, `AccountingLedger`, and `RewardVoucher`).

## Architectural Highlights

1. **Dual Push + Pull Ingestion (Webhooks + Parallel Periodic Polling)**
   - **Authenticated Bank Callbacks** (`POST /v1/webhooks/banks/:adapter_id`): Verifies bank-specific HMAC-SHA256 / RFC 7515 HS256 JWS signatures and ingests finalized incoming credits (`AppliedCreditEvent`) and outgoing payment state transitions (`OutboundPaymentStatusEvent`: `Initiated -> AcceptedByBank -> InProcessing -> Settled | Rejected | Failed | Returned`).
   - **Parallel `PollingSupervisor`**: Periodically polls corporate transaction statements (`poll_incoming_transactions`), non-finalized outgoing payment statuses (`poll_outbound_payment_status`), and acquirer settlement sweeps (`poll_settlement_batches`), converging into the exact same idempotent reconciliation engine.

2. **Hexagonal Port & Adapter Separation (Zero Business Logic Duplication)**
   - `src/engine/reconciliation.rs` contains **zero** bank URLs, OAuth2/HMAC headers, or proprietary JSON schemas.
   - Adding a new bank or payment processor only requires implementing `BankTechnicalAdapter` (`src/ports/bank_adapter.rs`) or `PaymentAcquirerAdapter` (`src/ports/acquirer_adapter.rs`).
   - Built-in technical adapters:
     - **`OcbcCorporateBankAdapter`** (`CONNECT2OCBC` OAuth2 + Credit Alerts + `transactionHistory/1.0` + FAST/PayNow/GIRO/MEPS+/TT `paymentInquiry/1.0`)
     - **`Iso20022BankAdapter`** (`camt.054` notifications, `camt.052`/`camt.053` statements, `pain.001` & `pain.002` status — reusable across DBS RAPID, Standard Chartered Straight2Bank, HSBCnet, Citi)
     - **`OcbcMerchantCardAdapter`** (`CONNECT2OCBC` Merchant Card Payments API — card auth/capture, refunds, inquiry, and EOD merchant card settlement batches)
     - **`StripeAcquirerAdapter`** (Stripe Checkout / PaymentIntents, refunds/disputes, and `payout.paid` + `/v1/balance_transactions?payout=po_...` periodical sweep decomposition)

3. **Multi-Entity (`AccountOwner`), Multi-Account, Multi-Currency & Counterparty Directory**
   - Supports multiple distinct corporate `AccountOwner` entities simultaneously, each owning multiple bank accounts across multiple banks and ISO 4217 currencies (`SGD`, `USD`, `EUR`, `JPY`, etc.), with strict tenant boundary enforcement and per-entity on-chain HFS bindings.

4. **Two-Stage Payment Acquiring vs. Asynchronous Bank Cash Finality Bridging**
   - Captures via **OCBC Merchant Card Payments API** or **Stripe** are booked into `1140 Merchant Acquirer Clearing Receivable` / `2450 Unsettled Order Clearing` (`CapturedPendingBankSweep`) — **never** prematurely treated as cash in bank.
   - Only when the acquirer's settlement batch / periodical sweep (`AcquirerSettlementBatch`) is matched off against the actual incoming `AppliedCreditEvent` on the entity's corporate `BankAccount` (supporting **both** arrival orders: manifest-first or bank-credit-first!) does the engine:
     1. Clear `1140` into `1010 Cash at Bank` + `6250 Bank & Acquirer Fees`
     2. Transition every constituent non-refunded payment to `BankCashFinalized`
     3. Queue finalized on-chain HFS transactions (`AssetLedger.charterModuleIssue`, `AccountingLedger.settleCreditInvoice`, `RewardVoucher.issuePaidVoucher`) in the persistent transactional outbox.
