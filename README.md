# `banking-oracle` — Multi-Entity, Multi-Bank & Payment Acquiring Oracle

Standalone, dependency-isolated Rust service connecting corporate commercial banking rails and merchant payment acquirers to SuperLexicon Haltproof Subroutines (`AssetLedger`, `AccountingLedger`, and `RewardVoucher`).

## Official CONNECT2OCBC Endpoints Implemented

1. **OCBC OAuth 2.0 Customer / Corporate Authorization (`src/adapters/ocbc_auth.rs`)**
   - `GET https://api.ocbc.com/ocbcauthentication/api/oauth2/authorize?client_id=<consumer key>&redirect_uri=<redirect URL>&scope=transactional` (exposed via `GET /v1/oauth/ocbc/authorize-url`)
   - Captures the `#access_token=...&token_type=Bearer&expires_in=3600` redirect fragment via `GET /v1/oauth/ocbc/callback` + `POST /v1/oauth/ocbc/token`
   - Passes both `Authorization: Bearer <access_token>` and `sessionToken=OAuth2INB <access_token>` and enforces OCBC's documented `10 API calls / minute` per-user rate limit.

2. **OCBC Corporate Transaction History (`src/adapters/banks/ocbc_corporate.rs`)**
   - `GET https://api.ocbc.com/transactional/corpTransHistory/1.0?sessionToken=OAuth2INB%20<token>&accountId=<id>&fromDate=<dd-mm-yyyy>&toDate=<dd-mm-yyyy>`
   - Parses `success`, `results[]` (`amount`, `debitCreditIndicator`, `transactionDate`, `currencyCode`), `errorMessage`, and `disclaimer`, with collision-proof, poll-idempotent entry identification and debit-side (`debitCreditIndicator == "D"`) outbound settlement tracking.

3. **OCBC Merchant Card Payments API (`src/adapters/acquirers/ocbc_merchant_card.rs`)**
   - `POST https://api.ocbc.com/transactional/merchantcardpayments/1.0/authorize`
   - `POST https://api.ocbc.com/transactional/merchantcardpayments/1.0/sale`
   - `POST https://api.ocbc.com/transactional/merchantcardpayments/1.0/capture`
   - `POST https://api.ocbc.com/transactional/merchantcardpayments/1.0/void`
   - `POST https://api.ocbc.com/transactional/merchantcardpayments/1.0/query`
   - Parses all documented `results` fields (`transactionId`, `merchantTranId`, `customerId`, `authId`, `responseCode`, `responseDesc`, `txnStatus`, `authDate`, `salesDate`, `captureDate`, `voidRevDate`, `tranDate`, `frScore`, `frLevel`, `txnSignature`, `txnSignature2`) + `disclaimer`, while keeping card captures strictly segregated in `1140 Acquirer Clearing Receivable` until matched off against the finalized deposit on `corpTransHistory/1.0`.
