package jwk

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"crypto/mldsa"
)

// RFC 9964 Appendix A.1 ML-DSA-44 test vector (all-zeros seed).
const (
	vecPub44  = "unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ"
	vecSeed44 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	vecJWS44  = "eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJUNHhsNzBTN01UNlplcTZyOVY5ZlBKR1ZuNzZ3Zm5YSjIxLWd5bzBHdTZvIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.knI1Q_9CIzLH5Xy94Kkc7WVKqZcAgtJ3mNf0GUj1uLA6YXAWFJfXkh-zQxUtEl3UIC7zPCiUwKTDR6ZsuUmFj8Ctb_6aH64hElN7weS_1m5okCy8GqHNL2lsfclCH3Y2f4QNP-DLVS1XsuboDA7Dw3ir2IdYKIfWJyIU7ROHgd24nuun1zJbxcLJC2EKt2M8R0wZudcIE9nm5oPzYXq0z-hPsKoXp9leVYkqgMmO9Lo8SP_1YYIEth3B8v-GuP249KDTFRKPjISmK4aPCknjtjihHsQVv2XePXxKExatHl4qhsiiW-y-EJXa1Kfw4WYpLA7B4_5Ids--cIJmIx7f6xxAWKh5qoBWq1QIOaaFuzsAraRW3NOEuzThew1En85gI3GcRTZGp-VDGyxHm0Al04cyWo2bxAVOF0fbDc265iP2mCNw6Qg10jIJeAhGB4OAMYcBUWJAG0l1MN1U_koEmGh5dXKnQTRl461ea_Cq3DLkcA2Dj2woWUFyDTmQ8oO_yheASfJacyRm7_suj88z5XFNo8F53P8OxTG9xUPlrwvH-TAq7AH3NU4SNXApyVKTU3zhx1tJ34nlTILcTujXVJVo_f0DZfUxr6JSCYqvy4z1Kl0wDQzd55aopyFtQxvOPhcCHbAN34g2Ug750Jm835fl7NOxcqoMbuTcgH68kr37M-Pdh2K9WazXUJgCupgdIWW8WjfOjmTiF59CrVtfVtK2qDzF40OENCfqtNPQlZe5cN5p0P8arj4USB8HCPh7NdqQBAeWrw0wsYhdiM39lrSkA8mLRYMhZnqKGCTPCrHXDdEjRKYRNaqIUT44laYl5c27K0v-ozjKPu6tzEhkYSC4XZ3LehEFtmAzOE0mHbhKMgXqjoPJjOrGIPibX3jwK8_Q5RmMOXtXo8R3vXfBaUdQoLeeyywNYE0nIcsl4z5a8_utwEFiVf0VK2pdviyiOPVSi3zOMAmqz6gFhVy8aMMQOWZAEAuTyDw7ZWG6diwptmrgSXZotW63I19S2ZH7keCXRIq_pFLuYhOuG6dD4MkouILRdC9bXZMLrNDq7COpUOO86aQVlYd0pR935WpUw-V6obSRnHlRFZSmUSIB7h1Q0ImciRzojN93Xhw7qpzGzdzDEO3OOTayXaSG_0YHQyy-eH4hBbmgt_LBx120g1eY4XHeHFRfTfetHkL5ZZusX1jQ_nk9ez4XBG_6hRtTNSuVBsYlH8-KUuR5-qTP8dkvRf8Wk2hHoUr2sz5YO_xDFCMMTrt8ahiMyfjo5ih5Fwo3riFbFUGKibniTLXspFd4spcNK_WchlZLRgkPK4jh6Z_X8JJkHxvQhpyouHQFyGxgBrl24x-_EB1zbWMhJthmm8DiKt-nzKaJz8Cju1-HwCpg76CRqRsEz2hyKEpbb4M5KQSj3AsENCroVmQ5QIv3K2XNRkve4vjBmP6sV2b6GSY_UeRvPElA7SUgBGTKbn-c0aYhBuB8plPhRTBa55_cFqAmNmavF1-fdMktJuIaH2f-K0zZCzbHw54998T7kIWgyMsyGCAvynEB_khOqwT7tCjg5HQ8SIjdnRYW0kjZfjt5LJbGA-PnRo8gPVQVGeYDP2vsSXhNJY94AitKCY1srcSsuYDrhNBKrnoJ1uEsMPVHsgFw_ZHMyAEaVQughSNW4fm8q6_1Nv4zLutDITzmAL6a6i6-WS6QRIs_4VUtwr5cXXIFDDeHVWeGcNivQ6W9urEUP4crguiq7z_DTiYaGfUksub-T7mw0zU8ZoOSd5pUTpJLv-IYIUAl6CscHvunnRLEKqpW1Sa1dcFZs5VP4AfR3mg7wX4Vlq1AHnpFxE2L1LZiKoTc9jDEOvTDkxr86gMkwMm6RdyPF_q48AVJ1br8Qp88-4B84X52zZ5cw-IJYe-HiVJ29LpeYm340_rWivpy-UB5i9TKlMrxf94y1okzZTPbP3_v1_XX0nE7RTLz98EA96euJ7l3EpbEqks7mh6i1FJNnvvlM_u29sYobJ6PUT-i1VlQnF_JBARKEz74pBXm1l5Y5Lo15rsIlaQHinUBCO8fHCHI59LAfKusN4JmodDqLYwkWijEL_sfrC6LtrbXqpM1pw09zSrs_tS1RQ-LnWHuPrU5KLCzv53JKrh8lU_cdBowe_F-Ib_Ui4bQ2FME-0mnyG0XijHUsrGMZ9dfowvIkr83JpqwlFOZAwMmSGPNPEJRw9kDshjotndUB5S1UCfv_U4IoVn7WgvxeCS-BBxqyWfh7YTdf73EnmGwVYxVjlXaHCeeTZmUacnT4MQUAcbFjTq6BBlboAQGWP2FZWpd6HNnruv744VeWmfgLk9z5567wFhwuXMkmE2xvDo4wP80xutjUfsePx5YkLxhY1XsWqTZr19tInxJWWq8RLZsWPmtq5wZ5ucBMasCLpOABenYZdSAcQNhC73wLS0Z2s1HQhBoIl7lr1p372LZs_Seu1u_8Fo7DoJqRpKaNoc2_JUMmn7TUZS8zLyzxgeq8R8iNbRP20DwDBNXocsTDBKaQrtB-QiEPySQtJa4G61XeNZyh5aGzfoWZ9OmjZG9pbbehcqwIrt-ESjPyeT6sfSrvOfTZr7fBXwpUs2rS4BrlNse5g_h8CQiik8aaOTOEPkXiyg4s5DewRlgDZHS-3g-YXPUIBNO62_HxknkMpkJvKW-tkvDbgtxvy4nG80ul6W_KeRsoEKDTRYNKZWxXjZITNa0h6agnwNCJKEbFg3Qhre394c0i60mfP9YIgKTXrCX3Yt2eX-6mPzYmLbSbV5jH69v6WZqYV2WAj-9DU0diR4hOfYQaJnBZhTtKb-SQsYiFuN1BDJ3v9eM9K8hq91NBdCHVa-Thk9Dov-JkcTZnZGRRyW5yXHUV4NOEltBXh8GkjjDvs5Yo3u-2rPCXjK1aGPSI1W8BaUJLQY5sbfAVCAuUHBv-Vlh5Qamt-lgeKguhqTSuy-tjabOb5kiBOG7xGQt3z-XYXtnWFDCii-5h11XfZsQ-xQxy8gSfdMz4hDK9Nw_VQt6fzWiQY0Th_dHzVki0MUfVfsDUjgblhD6j0wgbs3zdj-GM3rtt8oit0wXx11bIOaOKgf07tP0wimVXMRqRWe7LCUAKTE5PkRKU1x_h4iusrzi5uwKDhc4SmRwm6KssNrmCAkiNDZCREVKd3yMnrjA4PAGDzdKWVplcHJ6jKmrsbrEztHd9QAAAAAAAAAAAAAAABIfMEQ"
)

// TestRFC9964_Vector44 verifies the RFC 9964 Appendix A.1 ML-DSA-44 test
// vector: parse the all-zeros-seed JWK, derive the RFC 7638 AKP thumbprint
// kid, and verify the vector JWS signature with the registered golang-jwt
// signing method.
func TestRFC9964_Vector44(t *testing.T) {
	pubB64 := vecPub44
	seedB64 := vecSeed44
	jws := vecJWS44

	// Parse the vector JWK.
	jwkJSON := `{"kty":"AKP","alg":"ML-DSA-44","kid":"T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o","pub":"` + pubB64 + `","d":"` + seedB64 + `"}`
	k, err := ParseMLDSAJWK([]byte(jwkJSON))
	if err != nil {
		t.Fatalf("vector JWK parse: %v", err)
	}

	// RFC 9964 section 6: JWK thumbprint canonical members alg, kty, pub.
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	kid := base64.RawURLEncoding.EncodeToString(tp)
	if kid != "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o" {
		t.Errorf("AKP thumbprint kid mismatch:\n got %s\nwant T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o", kid)
	}

	// Verify the vector JWS at the JWS layer: the RFC payload is raw text
	// (not JSON claims), so the signature is checked directly against the
	// signing string via the registered golang-jwt method.
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("vector JWS is not compact: %d parts", len(parts))
	}
	signingString := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := SigningMethodMLDSA44.Verify(signingString, sig, k.MLDSPublicKey()); err != nil {
		t.Fatalf("vector JWS signature verification failed: %v", err)
	}

	// Header alg and kid match the vector JWK.
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != MLDSA44 {
		t.Errorf("vector alg = %q", hdr.Alg)
	}
	if hdr.Kid != kid {
		t.Errorf("vector kid = %q, thumbprint = %q", hdr.Kid, kid)
	}
}

func TestRFC9964_KeyValidationRules(t *testing.T) {
	// RFC 9964 section 3: the alg parameter is REQUIRED for all AKP keys.
	_, err := ParseMLDSAJWK([]byte(`{"kty":"AKP","pub":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 1312)) + `"}`))
	if err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Errorf("AKP JWK without alg must be rejected: %v", err)
	}

	// RFC 9964 section 5: pub sizes are 1312 / 1952 / 2592 bytes.
	for alg, size := range map[string]int{"ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592} {
		jwkJSON := `{"kty":"AKP","alg":"` + alg + `","pub":"` + base64.RawURLEncoding.EncodeToString(make([]byte, size+1)) + `"}`
		if _, err := ParseMLDSAJWK([]byte(jwkJSON)); err == nil {
			t.Errorf("%s pub of %d bytes must be rejected", alg, size+1)
		}
	}

	// RFC 9964 section 4: the priv seed MUST be 32 bytes.
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	jwkJSON := `{"kty":"AKP","alg":"ML-DSA-44","pub":"` + base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()) +
		`","d":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 31)) + `"}`
	if _, err := ParseMLDSAJWK([]byte(jwkJSON)); err == nil {
		t.Error("31-byte seed must be rejected")
	}

	// RFC 9964 section 3: priv MUST NOT be present in public keys —
	// marshalling never emits private material.
	k, err := NewMLDSAKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"d"`) || strings.Contains(string(b), "priv") {
		t.Errorf("marshalled AKP JWK leaks private material: %s", b)
	}
}
