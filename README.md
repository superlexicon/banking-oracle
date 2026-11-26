# `banking-oracle` — Multi-Entity, Multi-Bank & Payment Acquiring Oracle

Standalone, dependency-isolated Rust service connecting corporate commercial banking rails and merchant payment acquirers (**Airwallex**, **CONNECT2OCBC**, **ISO 20022**, and **Stripe**) to SuperLexicon Haltproof Subroutines (`AssetLedger`, `AccountingLedger`, and `RewardVoucher`).

## Airwallex Global Accounts & Payment Acceptance (`airwallex_bank` + `airwallex`)

1. **Shared OAuth Bearer Token Cache & Webhook Verifier (`src/adapters/airwallex_auth.rs`)**
   - `POST https://api.airwallex.com/api/v1/authentication/login` (`x-client-id` + `x-api-key`) with 30-minute Bearer token caching and `x-on-behalf-of` multi-entity sub-account support.
   - Verifies official Airwallex `x-timestamp` + `x-signature` (`HMAC-SHA256(webhook_secret, x_timestamp || raw_body)`) webhook headers with replay-window enforcement.

2. **Global Payment Acceptance & Pre-Order Crowdfunding (`src/adapters/acquirers/airwallex.rs`)**
   - `POST /api/v1/pa/payment_intents/create` (`auto_capture: true` for immediate sales, or `auto_capture: false` / `PaymentConsent` for hardware pre-order crowdfunding holds).
   - `POST /api/v1/pa/payment_intents/{id}/capture` & `/cancel` (capture when a Board-Resolution crowdfunding target unlocks, or cancel with zero charge if unmet).
   - `GET /api/v1/pa/financial/settlements` + `/report` with **like-for-like multi-currency settlement** (`USD` foreign cards settling into an Airwallex `USD` Global Account with `0%` forced FX conversion).

3. **Multi-Currency Global Accounts, Deposits & Transfers (`src/adapters/banks/airwallex_global.rs`)**
   - `GET /api/v1/deposits` (`SGD` `FAST`/`PayNow`, `USD` `ACH`/`Fedwire`, `EUR` `SEPA`, and card settlement sweeps).
   - `POST /api/v1/transfers/create` & `GET /api/v1/transfers/{id}` (automated domestic `FAST` and cross-border `LOCAL`/`SWIFT` supplier payouts).
   - `POST /api/v1/deposits/create` (`DIRECT_DEBIT` pull collections).

## Official CONNECT2OCBC Endpoints Implemented (7 APIs)

1. **OCBC OAuth 2.0 Customer / Corporate Authorization (`src/adapters/ocbc_auth.rs`)**
   - `GET https://api.ocbc.com/ocbcauthentication/api/oauth2/authorize?client_id=<consumer key>&redirect_uri=<redirect URL>&scope=transactional` (exposed via `GET /v1/oauth/ocbc/authorize-url`)
   - Captures the `#access_token=...&token_type=Bearer&expires_in=3600` redirect fragment via `GET /v1/oauth/ocbc/callback` + `POST /v1/oauth/ocbc/token`
   - Passes both `Authorization: Bearer <access_token>` and `sessionToken=OAuth2INB <access_token>` and enforces OCBC's documented `10 API calls / minute` per-user rate limit.

2. **Corporate Transaction History (`src/adapters/banks/ocbc_corporate.rs`)**
   - `GET https://api.ocbc.com/transactional/corpTransHistory/1.0?sessionToken=OAuth2INB%20<token>&accountId=<id>&fromDate=<dd-mm-yyyy>&toDate=<dd-mm-yyyy>`
   - Parses `success`, `results[]` (`amount`, `debitCreditIndicator`, `transactionDate`, `currencyCode`), `errorMessage`, and `disclaimer`.

3. **Perform MEPS Payment — Outbound Initiation (`src/adapters/banks/ocbc_corporate.rs`)**
   - `POST https://api.ocbc.com/transactional/corp/payment/meps/1.0`
   - Posts `{ ReferenceText, ValueDate, Payer: { AccountNo, Currency, SwiftCode }, Payee: { AccountNo, AccountName, BeneficiaryBankName, SwiftCode, Address: { Address } }, Amount: { Currency, Value } }` and parses `{ ReferenceText, Success, Disclaimer, Results: { BankPaymentId } }`.

4. **Retrieve Status of a MEPS Payment — Outbound Status Polling (`src/adapters/banks/ocbc_corporate.rs`)**
   - `POST https://api.ocbc.com/corp/payment/meps/1.0`
   - Posts `{ ReferenceText, AccountNo, AccountCurrency, ValueDate }` and maps `Results.PaymentStatus` (`SUBMITTED`, `PROCESSING`, `UNKNOWN`, `COMPLETED`, `FAILED`, `REJECTED`) + `BankPaymentId` + `UpdateDateTime` + `ActualValueDate` + `Amount`.

5. **Corporate PayNow Collection via UEN (`src/adapters/banks/ocbc_corporate.rs`)**
   - `POST https://api.ocbc.com/transactional/corporate/paynowcollection/1.0` (exposed via `POST /v1/collections/direct`)
   - Posts `{ TransactionDescription, Amount (double), ProxyType ("UEN"), ProxyValue, FromAccountNo, PurposeCode, TransactionReferenceNo, DDAReferenceNo }` and tracks `{ Result: { TransactionDescription, OCBCReferenceNo, TransactionReferenceNo } }` until the incoming PayNow credit clears.

6. **Enquire Details of PayNow Transactions (`src/adapters/banks/ocbc_corporate.rs`)**
   - `POST https://api.ocbc.com/ocbc/sg/corp/paynow/1.0`
   - Posts `{ PartnerID, FromDate, ToDate, AccountCurrency, AccountNo (double) }` and ingests finalized `CreditDebitIndicator == "C"` entries from `Transactions[]` (`AccountCurrency`, `AccountNo`, `Amount`, `CreditDebitIndicator`), automatically reconciling open PayNow UEN collections.

7. **OCBC Merchant Card Payments API (`src/adapters/acquirers/ocbc_merchant_card.rs`)**
   - `POST https://api.ocbc.com/transactional/merchantcardpayments/1.0/{authorize,sale,capture,void,query}`
   - Parses all documented `results` fields (`transactionId`, `merchantTranId`, `customerId`, `authId`, `responseCode`, `responseDesc`, `txnStatus`, `authDate`, `salesDate`, `captureDate`, `voidRevDate`, `tranDate`, `frScore`, `frLevel`, `txnSignature`, `txnSignature2`) + `disclaimer`, keeping card captures in `1140 Acquirer Clearing` until reconciled against the net deposit on `corpTransHistory/1.0`.
