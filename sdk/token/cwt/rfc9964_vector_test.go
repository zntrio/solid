package cwt

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"crypto/mldsa"
	"github.com/veraison/go-cose"

	"zntr.io/solid/sdk/jwk"
)

// RFC 9964 Appendix A.2 ML-DSA-44 COSE test vector (all-zeros seed).
const (
	vecCOSEPub44 = "ba71f9f64e11baeb58fa9c6fbb6e14e61f18643dab495b47539a9166ca0198131c44f826bbd56e34e55db5e5e2d733485e39ea260fc6000c5ea4ba80d3455cde53b46f34482aedfd5450fc2e1ba4f25d15f9c144242fb39bb52287189030c50498e1717b7c758b190a6748ea9aa3f7acaaf2c7cb526ed717c9f79aeb84214fa5cd8ded92a0c3fa1558810f12c7050a367708d196cd24e5af974904aed8e4ce8872e8696b0b7bca50e452cd7d30ea9a4adac0311d672c6bde8496240b07431463708895cd9bafc31632d7397649388fdafcbf7d305a3de9a495eca7433a8f83ba0f0b25c413c6e39c96eb7d691b34d37ce37f1eead1cf217e25ef34eecf3f7c60f84b8edfdde8405d4f832576c61ef98e0a2f28da187700953924f686b94614705bcf53d33fedd4348edddbdf28b5065e1f20775043e85cf931f829179363a1a7e7404a838ec00086b0976386fe637c98244757e3f769ddd4467471bfad670f9a05f8246ee50a7b1eaf87fc4069c3ae2aa2033258117792f0bcd49e083fd1bc7496abff29cc94e4868b21214ed316525399a610fbdd4a80e7c80715f29578e2a84bb40bdddbd9f47a11b6e7da118a1b658d359e8aef55eb46b5376b5b655979984a922beebfc59bcd600d5309dccd72dbf0787db8ba757b537c1eafd5c0f50ea4bc9583549e2829a42c28cac248c96d78124c47159b18aedd754aba17b19d430fb78f633ea9d26f54a9bd50f8d8f6b73594f828976e7ea09c53bbb9f11a56c9507fb89b9a5ebc037a37267a95f85b8d64ca97192b10a66f417b3f61fe9ca57130a48fd925eae2ab5502d571c8a51903c1d398f4c1f76a7e11743976afdbc697f23094a3cd761ff9685de32e09fb3c28add453490300bc7c89dc01780096071722945775f264e1b0623bcf4619c712c838761205d87691b75ef360196cbb9e9b92a0d4c4ed62326e5024d77510b8ee2c7426cc22eae209dc9f13bde6bf08f5e7181bd3b459450b451a51539a715c21d67dd330eb5970db00d9edbfb2822b036fa13bafeb86d8dc78866e3f8d43e53d78cca5595a6faf886b5dc112f1cf4adcfa875800d90b48883af97316fe1506873fc157e570eacbfd222868d14234101966afb6bf9940829253a953ada89fc756b6a849f70acb9838e69faa50bba75e3e89c2adb57e86d088ab9b04a28e670709172243ec5e0008a5ceaf3f8722f487302596ffd755ad1b82a49c34b3469515b46aa290cd86ee38ea7a9be3f103610335b531cca333ddfe32b14510f4b07ef95fc6684e8c454a92c10dbb5d59c7a7c63fb305fe881967d99e669eb632840582560bb403431d40f75a4954908482278292821f4ea91e42e78fa48caee3c836146dcfd738d117e92e9a15137d28e8e6a4b4622650cb413504cb3a335d44beec5746c1c294b1e8cb99cb608d928f8ce3563632c521f23d13c61a8f61c01df8c96c7360db4f3c68aa5d2fdd342a62ff3459c116389421ab43e8584c45882b50e6e4e96db6f0b8fde890d5dbfadcd88690b449e64240ddb2023747f308363e301aa77757169fc6150628d5920b5aa1ab1c8cbf44cb00e025d7879d72b479e3af5311c785725590da9c89b9fc3b8450769554eb44d203eba2bbaef9cad2237011c2ea44eff00f299a48ffe28ca93ddf85f76608242ef8d6cc24610a1e2078fcac4f9385c314905ecaa82e553916d94d1a7c1ec652aa08897083daa2ebb1775fbc471ae27777d7904ea9f1b92bcac3d8a3158426087b645b1108f0d65fec93789c053743ca14fd63d05e98b652df2b9c2ff9ce05f1940703ffb273f80e0e2732eca9960d981b4cfd3b7bb8045b3c3830546b9dd8db0d"
	vecCOSEKid44 = "b8969ab4b37da9f0684e42647eb8a0be8b5b661ebf5d76f0583bf5b8d3a8059a"
	vecCOSESign1 = "d2845827a201382f045820b8969ab4b37da9f0684e42647eb8a0be8b5b661ebf5d76f0583bf5b8d3a8059aa0581d68656c6c6f20706f7374207175616e74756d207369676e6174757265735909742657237b7520fd4cb8803f69a6e4ab613f4816420cd38e6474e548a370c6f0a18851ce8b7bb1b43c658b795303d0f22d23aad9afc7077877ab77d7cc92947bcf800e09626d7ceb809f74d2dc435200b272ecc92a993901087a42eaeaa6b9009df00f26055e6032ccca2995bf9c455e93c95adb9dda970ba07d778a9b4950169b289a86ec272bb810f9506b960941fa4ac804de49cb80f9bd54f51adef76670c06f94bf948ad7675ab28aa3254944753aac0cdbd8594752a438552e846fb476be3e31df0c91222db5e5d70bddb05b624a78103654d4e9ec514f6be91cfe8fa3b8529b2659a89e70227f35d0059362ed51c7523bf4a8ca7ceb0da6216bea77576548cd98f5ad6f87326facc8b308debce4461f1f2c4b190bd4950eec52cb66da70c9913e8a476826a0ea05edd8f2d3ca53e485ffcebc4e7ae33aeeb1d8dc3ee6b8d09cea138377ceeaed4fef57d868c16311e18c64b9df501791a6142085083850b3ad2e74901298c09b7fc4d87a660031e955b39cf9e6fbbe3cae5b36360f6b61f904771d55d542fbc68be5468738f5b8c44eb624da535a112c0266f79b9ae7ac996feab2c5874c65f59a72bf671b568d06e57b89f6fa168f48050f869e9fe0b95490487597e1746d7f54ef04eca32710bd4655a2269fd9afdfa0c7630c09ad59273d5d76f6bc026b623e5fee4fe3978efb4fdc5f905d8a346259cad9cd8ad826cdea818fcca6804bd78ddddb70d46d723ec63980fe7bb2eb8dab84692cb6f6a560eb80381dc0d5ded38d1de896772702f99637f6b9a9b207be86e2a401187bb250f68230f7840ecf9787bb6073e2e29f1287cd73bdf1dae8302fcf23f942305c4c9807aba037af66f8b278003c98a30084f9ad3f2e4c4b31eb1b3f20170c70f0310f71932a4e0065a2bd79eedc70e59f9cc261aed96fd7ebec86be2490789ad0dffc76f4cccc28ed675a769edf9f8d6e9fd78d59393687fb19b641626f70bbed7c6496a3a1393be6751f533e7af8f20f9ef32c7b58b231feb4231aa407ecf5e0be7921c449a537ab58871b4cef2f8b1212b189ddc9e207b0ebe8135be534b30f25ce0aa33371a94971da4b6b78bb2cb708035b539f3706348d1f6ef0e2ab9c741f1ffce5bd34c20c2ded6272c583188d2f48404cbd10f6aa759fecb1e5b87c755573db0d86ef17fecd7231179f47a19b0bcdafadad9a8b20dfe1d2792cc2d78d13c76722739d6c31563bc938fb07a0bc5d96d3a4e852141815b526ac74fa210c48ce1e2ffa3faa682191aea55a476a6cd7e0ab42902180b1444a2e08302c17608b5831daa4c4008dbb54f0b4ce566c069ed48d4a9c5b542816f3156cde0d7323bb071cccc98ee35672248e873b5907d02a153a57e5777c6767fd75e833df46813c2abe44dc6492e8de4487f4fa1d1377d4ae273d28869c6630ba4865e65676d9dc9ca0998a0082e95c78314d543068f6fd38a27bdbc98f8b5fefa21e704e4bc8ac7ed46ea5c03eb700cf0e549b8a1c50b5d051bd7c2588938f7c9f5499e7b95430b1e567a2e36b4a55252829d7fb319c7edab4e19108fa2a784c96ec1027f19f571448132b6c8c4441a7a7488ddda530b84ba0221120c95311eab37660b1329a70365117eebbb7e0240cc5052ec723e0121c2a175053c762b88943ac7b965d10239c4b8f8d39a1a57ace097a1631c7e93c36abc8a085a21a18a14b621cff49369707891e06e508e41970b26490c8f5c038bcb2e62a72d24591f563c42fed3dfa3539f75dacbc7918919642220a01da483a2c0413360e424c6cc30dfc502858a57ffdc20d30bb57c1659a7d4beb6794c4675524e813a27e3807547d0bc16e91242d7925b01f0a8cf03f5c6e867710373ad02e53816f82a21b2c9f359e7d586ec0590c0a1780a6755e1723981ebd866d251e20a0a5b2dc08e05beb325797aa7c2746596c534964cc751ff341d49e39c8b6f8a903549779189c5732b841abde352eddff9ffb67f20b9c27d30078994ac96c8250b3428c65a714c05c91c897a18ee58f908557062bd733444a9d73ed89a637c62143e46e1cb3723c6a8fd2df0d90d03b6cdfb4e6c033f67c51a803b6eaea79e0ecfe4a3b22c5dc951d51683ea716149958c59ab43f1085d8e5896aa3c8d972d54998d3de2b27c2d67e0059b78dff6f804cd491dfae0308b4c8983ea1c574b4414df8ca772fbb60dc49249f8dbab9c43357016893f7a4b2eb28c0a8de635157b717e20ad60d5a52d37e2ebf5b87dcdcccddd1f40825d56b948e60015118e8988f6000dd157ce92a0f0ec1d5459890317ee861a0d29f7305331047886e1918b8438d1df534e685c93f2f11317b000b0bd7da766e5f1d4a0816a7af878be4c8dc8fdd208abd5c7f98aa0e882772387ef5032f60e71a7c1c630a8eacdde2a7c5e86277b20e1317cd8b9892e8509647d55143dccca07ffdd678d5856eaab93f55df72ff4c909146de54393aeed095cbd9fc1a24b7f7950cb80eb423ed114cdc21e59593b2a5fcbbdf1613810fd63c8dd45e39bc5bd02d71328cfea87d2deadda75089ca7d4529e0b5b64fb887fc38cb9531033386255c6a155af95447b2154354e6d163b752bef91f248b5068f3e620365c8c497cfcbe61930d0cf08387308310f485bfa23c31bf2d01900e801352a388c97212ef58b6a81f5082f08831433a7ca8c0df910cc462b36d61f532325eeee540547b6c07c738b010daf7384f8cf01975761101e556e8639848dfd049ee5360bb9b62bb38aef0fc84970dad3e78c0f3413573042abe52805b5aec545bcb43142f5d44a9c1d2b6cdf3ded20907f02ebc78e78f598beadd0fc1faa676560edffbd7a83b61795bc29b6fbe4c7c6e9097139dbb85b54a8b446a37f2fd6a7db528f1c5da5fe367823f8fa39adae0bd23196f689059e2de3cfcbaad6bec710464156cd72be70d5950075953286feb605f6898746586750e3aef767b0e80136453c1ab388ff5462bfc0316ed78937ea235dd883e9fedbd66f9060b542272ac9747fe3109a27a89403fc1c2380ccb1e3f199077582aa565fba4621092c5665f2f7803f5ecfdaf86878ec045a780ea3751bd32333cd02fef8b4eb9386f51fa7a5f3bb81c55fb0de38c905ba4002dadfcc5123bf561bef2d32c40577dc487736162c69444279d917abd0d2320fb715299c1043defb582a20fec3190a6c0e484360910388889c122c4a13adc73031a0969e3c1a9008d8467c4c4d59c848d9ca2441ec57b02034fd5872b4cf75185d5fb14e6af1aead0e1727db42db39877f01d674558f7b59b0e0f10363e3f505d82a7c0c7cadd1618233541424f57596476777d80a6b8dfe6eefcfd0515196c8e99c3cfd2ebf2020b0c16202b3337484e525657a4b5bec3cad2d4d5d6dd00000000000000000000000e232e45"
)

// TestRFC9964_COSERoundTrip verifies the RFC 9964 Appendix A.2 ML-DSA-44
// COSE_Sign1 test vector through the external cose.Signer / cose.Verifier
// implementations: decode the vector, verify its signature with the
// external ML-DSA verifier, and check the protected alg header carries the
// RFC 9964 COSE algorithm value (-48).
func TestRFC9964_COSERoundTrip(t *testing.T) {
	raw, err := hex.DecodeString(vecCOSESign1)
	if err != nil {
		t.Fatal(err)
	}

	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(raw); err != nil {
		t.Fatalf("vector COSE_Sign1 decode: %v", err)
	}

	// Build the vector public key as a solid AKP key.
	pubBytes, err := hex.DecodeString(vecCOSEPub44)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	akp, err := jwk.NewMLDSAKeyFromPublic(pub)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the vector signature through the external RFC 9964 verifier.
	verifier, err := coseVerifierMLDSAForKey(akp)
	if err != nil {
		t.Fatal(err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		t.Fatalf("vector COSE_Sign1 verification failed: %v", err)
	}

	// Protected alg header carries the RFC 9964 COSE value for ML-DSA-44.
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		t.Fatal(err)
	}
	if alg != AlgorithmMLDSA44 {
		t.Errorf("vector alg = %v, want %v (ML-DSA-44)", alg, AlgorithmMLDSA44)
	}

	// Vector payload is the well-known test message.
	if !bytes.Equal(msg.Payload, []byte("hello post quantum signatures")) {
		t.Errorf("unexpected payload: %q", msg.Payload)
	}

	// kid in the protected header matches the vector key kid.
	if kid, ok := msg.Headers.Protected[cose.HeaderLabelKeyID]; ok {
		if !bytes.Equal(kid.([]byte), mustHex(t, vecCOSEKid44)) {
			t.Errorf("vector kid mismatch: %x", kid)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRFC9964_MLDSASignVerifyRoundTrip proves the full CWT signer/verifier
// path with ML-DSA: an AKP key is signed through DefaultSigner and the
// resulting COSE_Sign1 verifies through DefaultVerifier, mirroring the
// JOSE-side ML-DSA support.
func TestRFC9964_MLDSASignVerifyRoundTrip(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	akp, err := jwk.NewMLDSAKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := jwk.AssignKeyID(akp); err != nil {
		t.Fatalf("unable to assign kid: %v", err)
	}

	claims := map[string]any{"iss": "https://as.example.com", "sub": "someone"}

	// Sign through the CWT serializer with the ML-DSA-65 COSE algorithm.
	signer := DefaultSigner("at", AlgorithmMLDSA65, func(ctx context.Context) (jwk.Key, error) {
		return akp, nil
	})
	raw, err := signer.Serialize(context.Background(), claims)
	if err != nil {
		t.Fatalf("ML-DSA CWT signing failed: %v", err)
	}

	// Verify through the CWT verifier with the same allowlist entry.
	akpPub, err := akp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	set := jwk.NewSet()
	if err := set.Set("keys", []jwk.Key{akpPub}); err != nil {
		t.Fatal(err)
	}
	verifier := DefaultVerifier(func(context.Context) (jwk.Set, error) {
		return set, nil
	}, []cose.Algorithm{AlgorithmMLDSA65})
	var out map[string]any
	if err := verifier.Claims(context.Background(), raw, &out); err != nil {
		t.Fatalf("ML-DSA CWT verification failed: %v", err)
	}
	if out["sub"] != "someone" {
		t.Errorf("claims round-trip lost sub: %v", out)
	}

	// An ES-only allowlist must reject the ML-DSA token (fail closed).
	ecOnly := DefaultVerifier(func(context.Context) (jwk.Set, error) {
		return set, nil
	}, []cose.Algorithm{cose.AlgorithmES256})
	if err := ecOnly.Claims(context.Background(), raw, &out); err == nil {
		t.Error("ML-DSA token must be rejected by an ES-only allowlist")
	}
}

// TestRFC9964_AllowlistExtension proves the signer allowlist now covers
// ML-DSA alongside elliptic curves, mirroring the JOSE allowlist.
func TestRFC9964_AllowlistExtension(t *testing.T) {
	for _, alg := range []cose.Algorithm{cose.AlgorithmES256, cose.AlgorithmES384, cose.AlgorithmES512, AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87} {
		if err := enforceAlgorithmAllowlist(alg); err != nil {
			t.Errorf("algorithm %v must be allowed: %v", alg, err)
		}
	}
	for _, alg := range []cose.Algorithm{-257, -37, 0} {
		if err := enforceAlgorithmAllowlist(alg); err == nil {
			t.Errorf("algorithm %v must be rejected", alg)
		}
	}
}
