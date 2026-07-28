package protocol

import "strconv"

const (
	RevenueBatchPath = "/v1/revenue/batches"

	RevenueKind                  = "daily-revenue"
	RevenueRulesetVersion        = "net-captured-revenue-v1"
	RevenueCommissionBasisPoints = int64(500)
	RevenueEntryType             = "REVENUE_BATCH_ACCEPTED"

	MaximumRevenueCurrencyRows = 32
	MaximumRevenueMinor        = int64(9_000_000_000_000_000)
	MaximumRevenuePaymentCount = int64(1_000_000_000_000)
)

type RevenueCurrency struct {
	CurrencyCode             string `json:"currency_code"`
	FractionDigits           int64  `json:"fraction_digits"`
	CapturedMinor            int64  `json:"captured_minor"`
	RefundedMinor            int64  `json:"refunded_minor"`
	NetMinor                 int64  `json:"net_minor"`
	CommissionBasisMinor     int64  `json:"commission_basis_minor"`
	EstimatedCommissionMinor int64  `json:"estimated_commission_minor"`
	PaymentCount             int64  `json:"payment_count"`
}

type RevenueBatchRequest struct {
	ProtocolVersion           string            `json:"protocol_version"`
	RegistryScope             string            `json:"registry_scope"`
	DeploymentID              string            `json:"deployment_id"`
	Timestamp                 string            `json:"timestamp"`
	Nonce                     string            `json:"nonce"`
	IdempotencyKey            string            `json:"idempotency_key"`
	Kind                      string            `json:"kind"`
	Period                    string            `json:"period"`
	Revision                  int64             `json:"revision"`
	SupersedesBatchID         string            `json:"supersedes_batch_id"`
	RulesetVersion            string            `json:"ruleset_version"`
	CommissionRateBasisPoints int64             `json:"commission_rate_basis_points"`
	Currencies                []RevenueCurrency `json:"currencies"`
	PayloadHash               string            `json:"payload_hash"`
	Signature                 string            `json:"signature"`
}

type RevenueReceipt struct {
	LedgerIndex               int64  `json:"ledger_index"`
	EntryHash                 string `json:"entry_hash"`
	PreviousEntryHash         string `json:"previous_entry_hash"`
	BatchHash                 string `json:"batch_hash"`
	Kind                      string `json:"kind"`
	Period                    string `json:"period"`
	Revision                  int64  `json:"revision"`
	SupersedesBatchID         string `json:"supersedes_batch_id"`
	RulesetVersion            string `json:"ruleset_version"`
	CommissionRateBasisPoints int64  `json:"commission_rate_basis_points"`
	CurrencyCount             int64  `json:"currency_count"`
	AcceptedAt                string `json:"accepted_at"`
	CheckpointDate            string `json:"checkpoint_date"`
	RegistryScope             string `json:"registry_scope"`
	RegistryKeyID             string `json:"registry_key_id"`
	RegistryPublicKey         string `json:"registry_public_key"`
	Signature                 string `json:"signature"`
}

type RevenueBatchResponse struct {
	ProtocolVersion string         `json:"protocol_version"`
	RegistryScope   string         `json:"registry_scope"`
	BatchID         string         `json:"batch_id"`
	DeploymentID    string         `json:"deployment_id"`
	IdempotencyKey  string         `json:"idempotency_key"`
	Duplicate       bool           `json:"duplicate"`
	Receipt         RevenueReceipt `json:"receipt"`
}

type RevenueSummary struct {
	Period                    string `json:"period"`
	CurrencyCode              string `json:"currency_code"`
	FractionDigits            int64  `json:"fraction_digits"`
	DeploymentID              string `json:"deployment_id,omitempty"`
	DeploymentCount           int64  `json:"deployment_count"`
	ActiveBatchCount                   int64  `json:"active_batch_count"`
	CurrencyBatchCount                 int64  `json:"currency_batch_count"`
	CapturedMinor                      int64  `json:"captured_minor"`
	RefundedMinor                      int64  `json:"refunded_minor"`
	NetMinor                           int64  `json:"net_minor"`
	CommissionBasisMinor               int64  `json:"commission_basis_minor"`
	NetworkCommissionPoolMinor         int64  `json:"network_commission_pool_minor"`
	ReportedEstimatedCommissionMinor   int64  `json:"reported_estimated_commission_minor"`
	PaymentCount                       int64  `json:"payment_count"`
	RulesetVersion                     string `json:"ruleset_version"`
	CommissionRateBasisPoints          int64  `json:"commission_rate_basis_points"`
}

func RevenuePayload(
	kind string,
	period string,
	revision int64,
	supersedesBatchID string,
	rulesetVersion string,
	commissionRateBasisPoints int64,
	currencies []RevenueCurrency,
) []byte {
	lines := []string{
		"myscoutee-registry-revenue-batch-payload-v1",
		kind,
		period,
		strconv.FormatInt(revision, 10),
		supersedesBatchID,
		rulesetVersion,
		strconv.FormatInt(commissionRateBasisPoints, 10),
		strconv.Itoa(len(currencies)),
	}
	for _, currency := range currencies {
		lines = append(
			lines,
			currency.CurrencyCode,
			strconv.FormatInt(currency.FractionDigits, 10),
			strconv.FormatInt(currency.CapturedMinor, 10),
			strconv.FormatInt(currency.RefundedMinor, 10),
			strconv.FormatInt(currency.NetMinor, 10),
			strconv.FormatInt(currency.CommissionBasisMinor, 10),
			strconv.FormatInt(currency.EstimatedCommissionMinor, 10),
			strconv.FormatInt(currency.PaymentCount, 10),
		)
	}
	return canonical(lines...)
}

func RevenueReceiptMessage(
	protocolVersion string,
	registryScope string,
	batchID string,
	deploymentID string,
	ledgerIndex int64,
	entryHash string,
	previousEntryHash string,
	batchHash string,
	kind string,
	period string,
	revision int64,
	supersedesBatchID string,
	rulesetVersion string,
	commissionRateBasisPoints int64,
	currencyCount int64,
	acceptedAt string,
	checkpointDate string,
	registryKeyID string,
) []byte {
	return canonical(
		"myscoutee-registry-revenue-receipt-v1",
		protocolVersion,
		registryScope,
		batchID,
		deploymentID,
		strconv.FormatInt(ledgerIndex, 10),
		entryHash,
		previousEntryHash,
		batchHash,
		kind,
		period,
		strconv.FormatInt(revision, 10),
		supersedesBatchID,
		rulesetVersion,
		strconv.FormatInt(commissionRateBasisPoints, 10),
		strconv.FormatInt(currencyCount, 10),
		acceptedAt,
		checkpointDate,
		registryKeyID,
	)
}

func RevenueCommissionMinor(commissionBasisMinor int64) int64 {
	return (commissionBasisMinor/10_000)*RevenueCommissionBasisPoints +
		((commissionBasisMinor%10_000)*RevenueCommissionBasisPoints)/10_000
}

func ISO4217FractionDigits(code string) (int64, bool) {
	fractionDigits, ok := iso4217FractionDigits[code]
	return fractionDigits, ok
}

// Active ISO-4217 monetary and fund codes supported by revenue protocol v1.
// Precious-metal, test, accounting-unit, no-currency, and withdrawn codes are
// intentionally excluded because deployment revenue must be denominated in a
// settlement currency with a deterministic minor-unit exponent.
var iso4217FractionDigits = map[string]int64{
	"AED": 2, "AFN": 2, "ALL": 2, "AMD": 2, "ANG": 2, "AOA": 2,
	"ARS": 2, "AUD": 2, "AWG": 2, "AZN": 2,
	"BAM": 2, "BBD": 2, "BDT": 2, "BGN": 2, "BHD": 3, "BIF": 0,
	"BMD": 2, "BND": 2, "BOB": 2, "BOV": 2, "BRL": 2, "BSD": 2,
	"BTN": 2, "BWP": 2, "BYN": 2, "BZD": 2,
	"CAD": 2, "CDF": 2, "CHE": 2, "CHF": 2, "CHW": 2, "CLF": 4,
	"CLP": 0, "CNY": 2, "COP": 2, "COU": 2, "CRC": 2, "CUP": 2,
	"CVE": 2, "CZK": 2,
	"DJF": 0, "DKK": 2, "DOP": 2, "DZD": 2,
	"EGP": 2, "ERN": 2, "ETB": 2, "EUR": 2,
	"FJD": 2, "FKP": 2,
	"GBP": 2, "GEL": 2, "GHS": 2, "GIP": 2, "GMD": 2, "GNF": 0,
	"GTQ": 2, "GYD": 2,
	"HKD": 2, "HNL": 2, "HTG": 2, "HUF": 2,
	"IDR": 2, "ILS": 2, "INR": 2, "IQD": 3, "IRR": 2, "ISK": 0,
	"JMD": 2, "JOD": 3, "JPY": 0,
	"KES": 2, "KGS": 2, "KHR": 2, "KMF": 0, "KPW": 2, "KRW": 0,
	"KWD": 3, "KYD": 2, "KZT": 2,
	"LAK": 2, "LBP": 2, "LKR": 2, "LRD": 2, "LSL": 2, "LYD": 3,
	"MAD": 2, "MDL": 2, "MGA": 2, "MKD": 2, "MMK": 2, "MNT": 2,
	"MOP": 2, "MRU": 2, "MUR": 2, "MVR": 2, "MWK": 2, "MXN": 2,
	"MXV": 2, "MYR": 2, "MZN": 2,
	"NAD": 2, "NGN": 2, "NIO": 2, "NOK": 2, "NPR": 2, "NZD": 2,
	"OMR": 3,
	"PAB": 2, "PEN": 2, "PGK": 2, "PHP": 2, "PKR": 2, "PLN": 2,
	"PYG": 0,
	"QAR": 2,
	"RON": 2, "RSD": 2, "RUB": 2, "RWF": 0,
	"SAR": 2, "SBD": 2, "SCR": 2, "SDG": 2, "SEK": 2, "SGD": 2,
	"SHP": 2, "SLE": 2, "SOS": 2, "SRD": 2, "SSP": 2, "STN": 2,
	"SVC": 2, "SYP": 2, "SZL": 2,
	"THB": 2, "TJS": 2, "TMT": 2, "TND": 3, "TOP": 2, "TRY": 2,
	"TTD": 2, "TWD": 2, "TZS": 2,
	"UAH": 2, "UGX": 0, "USD": 2, "USN": 2, "UYI": 0, "UYU": 2,
	"UYW": 4, "UZS": 2,
	"VED": 2, "VES": 2, "VND": 0, "VUV": 0,
	"WST": 2,
	"XAF": 0, "XCD": 2, "XCG": 2, "XOF": 0, "XPF": 0,
	"YER": 2,
	"ZAR": 2, "ZMW": 2, "ZWG": 2,
}
