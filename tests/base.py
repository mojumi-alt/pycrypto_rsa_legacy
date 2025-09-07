import unittest
import base64
import typing

PRIVATE_KEY_E = 65537
PRIVATE_KEY_N = 3378821839439738615293440305222887901279058990761646481800953682110161855376131652220545743454808306884883933212600035780702888458658303902165964200930912475512476774188779938343309051984209986626152236128316140310500162197667837534328242031792521683298890981659627351638171818193519344165447989586480669624676278431922960853377007243752653391455400887260935257635403372900266768896297798773592371612516170208936965988750502999911173932205958723438919205230642310540717236670875133099947046914982932533373700127794675373428322461886611895656342396479984432832798848717174902447747098789600680878860352507381340748070471228080160027484928206733876127671070008057781284670381914850556004960613401369852188068561178513827997687686973131724470752226452711538413537642515853846565762888471867648783804884356994629149846089214120945972013946005025954961907466061025754687466928497376960953605542152353177664000413334493148941421169
PRIVATE_KEY_D = 27973395431323957108421692869811738820854317775771803514307451546733478595238813173738973576801726360843848117790000092782393287703033167914056935919482087889362416493409761125462569791961272796184950497977562788401547416051257674018761900235746103575027693238915718966024455280042831339372201784485069044873210614958281070383063122312680275050437304088982749518674071340049179512188782631458641596310853390998454544192281364003567518440719233980182699525022394550601076540987470209083194412574126148838438678586102714608480400330215195149038160557183909540785781130339425119406260066165250688593425095558306963451168203789903098236845424468126696865527436229392474670371055234718424507138623708793571688353904418100194867666617381651876136853239935171845076867830362896197886963313006342228376432999783246421337074621551385159651053141923267526595638856973848673849132236823312819216160262138922933965764133498531880609409
PRIVATE_KEY_P = 1949235894132590667538540021675320144478317115212882911029948547601889982936058565300139643945252838666720771020077264327901845403077894169876628884933059152218053450717726917401802356342062475838117853658469458491630493868684117511947706629707057785415435629661493799255403606261273951071925376176142756707151225928139053458365891995147094715921820834854642329524250271973471265261554599297883518283270644949831507381694445517923819417387994278805258952537327313
PRIVATE_KEY_Q = 1733408383054280469076654491588542212875038604859318312755774082960550190788227762176783599195168082919629845926817366998890325633730905115843583486138403958103661089252965250399400659397079511224464833884891555559141902614990652273381836590019344276804675634420417526495606983893285564521461212813466587296359377461077826647678306757445128730028388446910555302779347818944251361337442635981841469774218756097410106497275496387122469698245631167825944470353719713
PRIVATE_KEY_U = 927208216441242498111964267507302903072765935070145811530346619595150397425475822612033748910240494801963958586616654518683090766134266615792735602313383768944707585270623701962695159903233972568682086080157753277732846420004850795969910477101099678549049913680353941488489910277157485277835504963989663196779503802976433996968510268623465697266435983994164255312134593633556844737807773161425175602343406148117507583415237535265020060641905474873350826970882500

MESSAGE_TEXT_SHORT = "TEST 1 2 3 5"
CIPHER_TEXT_SHORT = "OC0wvqPBgAhGpuzFfuQm59vf+sZWHANdtWLlHEdaLw7t3TqYghjTFzIUgTHzt7gCEEFzx6aWEUduGKN2rWUqTrFW/CdpAZiu+xtYHLnBZ4WO31BEwC2yYZfTgcptwAH3ONpTbrK7TYc8ATU5Aduf69h8ZyoMcZwwvtjTWBbrKr4lmmhb0QdoNAPWp/o6F3GEKZgqXc5Cke1UWgHTr4k6IS8Zsa82A/zJLkp/OwmpIuw1ENfAlANGvtiZStVhzyJXijpbFnDO2fEzPpBKBU80k7Yxgdl9QBCR9Bxw3cl1Gy8RugPu5ERgW4JLovdr/Yi5D2FP/Wu8oWSbmPS5Sfcj1akGW8fd1Po1DWX2MBwmbx8fXHm29VoRASWKoBHhVAk+/fnNnHjFuPxE91ZRJXsQoLAuJcy6unxFZMie3DrpImMWgQ+ckM3LZWoHQozYIvFZKIUXumMk5BTlxpa7pHkeuJ60ZeDDc2aYEg7620rrJY9GSfNSKnIZa/iIAHyeR992"
SIGNATURE_SHORT_TEXT = "ivdnsEQg21jc9BasW45QUCDwN9lSw9vnZzxPAO051XvSxyu+T0GUkiWS51G5R4KDUslDjdUh5JDgZ/0Xi5CHkdwE1fXiFRgDpvbLbBcu8BUbIX+bTsGXR8D4ywAUUsvar7KS2nTFvcHF9Dmy6Hlt4Ww7hxlUe7XNG/EkY9awhc4nIUBuj1av7XDQxdmVo4YBxP1qS114cpcQS+pmnsXeMPTUO9zmlTTGPsC/Mjw7ng6rbU6anYS4Fx/U27KE2QbHyYa/Gv+Mvb7Du7zcmqKts5ob1JzmTVl7F+npQ6S20pbiczBwqkJxbXmXhLP8bADJ1um6cD9w7U4siTHkkuT0qO2AlpNLAIKsM8v9j69LhoB08ninQVBj1MkQSr4v4V65tn9Nyt6Oe/xEoMuoPmD+evD4zcyowv5LvXw6HaZ96XqlcD5K+xZ8EkTo72Y7FbrFkd4W3vNhTPQgUnG4wq6+KjwmrDf7Rirvr/oaclcecs01pbMm28LDslpDLl6CqvN1"

MESSAGE_TEXT_LONG = "Some slighty longer text that still does not overflow"
CIPHER_TEXT_LONG = "G33hWyuEnpoQMo1SX9I10KOxCNAGiB9JBsGtsinPyhHcvPR37aDijKr2lNcHyeAB03ABjY30A9lijWBsVe/lSSLXNQIa0khBLy+79ULK1iEAn7eWjWvvUEKCwY+xmGKyUkfPkr5RFT6hmZNr9hiqSMZ3htwFq4QiSPyV8bePwNIMeoV8wk36rT6SQc9IVfgbqNiN0RU83YnAdd0H7szsmMhPaLWAhuhdEVApGHMehCfSwaMVI9HoTaYMNQrvtCEf87eo4epQ7GCwVmXXeg+p2cDA8JlXQhAlv6+SmFDMP+YD6vMF3MD8tDpw73BQ6zOAQYKgRnTo8My4+4S/0WFdXvL/nRvkzzUNn26IprAF8YsHK9cAliEA3PUESa8NXafLVUHpf6GwUokVRBM9f9vhmhrex9kaWD2pDVsLrzrIjagIZyosu4FoE06Q+ygTynFCMDNyLhw5hyzdMjTpyiNhhW+9q4zksaFgj41mzxJJSw0nda6B5lmLzPYy60SBPV0z"
SIGNATURE_LONG_TEXT = "fvdi4jYjxhncvfG4miDv3jfFyvR7YRuOn3CrIMTPVergE9fC08ah7mut1QxqF3XlSRrADwn+5YCt1fjHV+cbGvcmtGcki0Z1dYHOEHdt7RNT9QJSEQp6EtRqqsYs3HudTNxrUlGoRf7u9r1q9qNttTuNLaWP5J7snx+MI3zGFxV3NuHxi75HoE+lJW9gr6IS6fwCrmd4e9TN0lG3B3WzhH8cW0zpKDtEJHyHDe50e0tZn+6zPw6iiDWcxKWyMTNiFiIMELb6YYfs+O5UdM3USxagyqApN9pTlt7PP7ZAFSirwm1gS4J6C5bdnoj9uXHKvXENr3VYT6vnC4OIbnI8pDHdJMjofN7tLXO27nkupEShDCgd4uwOOJRr47GCurlhcGO8ZbzhrYztH4v46tr3bGFBMWKVZ70EN453azoXlgNA/278dqKx40pBNDQ4Va90peUWB5KDmi0PS0wrv4FRhYW/CRQBg4mpVus4afOYFkjoXxljB2PkzLdai87yme/V"

MAX_MESSAGE_LENGTH = 3071


class ExampleKey:
    e: int = PRIVATE_KEY_E
    n: int = PRIVATE_KEY_N
    d: int = PRIVATE_KEY_D
    p: int = PRIVATE_KEY_P
    q: int = PRIVATE_KEY_Q
    u: int = PRIVATE_KEY_U


class AbstractTests:
    class TestRSA(unittest.TestCase):

        def get_key_implementation(self):
            raise NotImplementedError()

        @staticmethod
        def to_base64(byte_string):
            return base64.b64encode(byte_string).decode()

        @staticmethod
        def from_base64(b64_string):
            return base64.b64decode(b64_string.encode())

        def make_key(self):
            return self.get_key_implementation()(
                PRIVATE_KEY_N,
                PRIVATE_KEY_E,
                PRIVATE_KEY_D,
                PRIVATE_KEY_P,
                PRIVATE_KEY_Q,
                PRIVATE_KEY_U,
            )

        def test_encryption_short(self):
            encrypted_text = AbstractTests.TestRSA.to_base64(
                self.make_key().encrypt(MESSAGE_TEXT_SHORT.encode("utf-8"))
            )
            self.assertEqual(encrypted_text, CIPHER_TEXT_SHORT)

        def test_encryption_long(self):
            encrypted_text = AbstractTests.TestRSA.to_base64(
                self.make_key().encrypt(MESSAGE_TEXT_LONG.encode("utf-8"))
            )
            self.assertEqual(encrypted_text, CIPHER_TEXT_LONG)

        def test_decryption_short(self):
            decrypted_text = (
                self.make_key()
                .decrypt(AbstractTests.TestRSA.from_base64(CIPHER_TEXT_SHORT))
                .decode()
            )
            self.assertEqual(decrypted_text, MESSAGE_TEXT_SHORT)

        def test_decryption_short_pqu(self):
            decrypted_text = (
                self.make_key()
                .decrypt(AbstractTests.TestRSA.from_base64(CIPHER_TEXT_SHORT))
                .decode()
            )
            self.assertEqual(decrypted_text, MESSAGE_TEXT_SHORT)

        def test_decryption_long(self):
            decrypted_text = (
                self.make_key()
                .decrypt(AbstractTests.TestRSA.from_base64(CIPHER_TEXT_LONG))
                .decode()
            )
            self.assertEqual(decrypted_text, MESSAGE_TEXT_LONG)

        def test_decryption_long_pqu(self):
            decrypted_text = (
                self.make_key()
                .decrypt(AbstractTests.TestRSA.from_base64(CIPHER_TEXT_LONG))
                .decode()
            )
            self.assertEqual(decrypted_text, MESSAGE_TEXT_LONG)

        def test_message_text_too_big(self):
            self.assertRaises(ValueError, self.make_key().encrypt, b"a" * 1000)

        def test_cipher_too_big(self):
            self.assertRaises(ValueError, self.make_key().decrypt, b"a" * 1000)

        def test_no_private_key(self):
            key = self.make_key()
            key.e = None
            self.assertRaises(ValueError, key.encrypt, b"a")

        def test_no_public_key(self):
            key = self.make_key()
            key.d = None
            self.assertRaises(ValueError, key.decrypt, b"a")

        def test_max_message_length(self):
            self.assertEqual(
                self.make_key().max_message_length_bits, MAX_MESSAGE_LENGTH
            )

        def test_public_key(self):
            key = self.get_key_implementation()(PRIVATE_KEY_N, PRIVATE_KEY_E)
            self.assertEqual(key.is_private_key, False)
            self.assertEqual(key.is_public_key, True)

        def test_private_key(self):
            key = self.get_key_implementation()(PRIVATE_KEY_N, d=PRIVATE_KEY_D)
            self.assertEqual(key.is_private_key, True)
            self.assertEqual(key.is_public_key, False)

        def test_sign_short_message(self):
            signed_text = AbstractTests.TestRSA.to_base64(
                self.make_key().sign(MESSAGE_TEXT_SHORT.encode("utf-8"))
            )
            self.assertEqual(signed_text, SIGNATURE_SHORT_TEXT)

        def test_sign_long_message(self):
            signed_text = AbstractTests.TestRSA.to_base64(
                self.make_key().sign(MESSAGE_TEXT_LONG.encode("utf-8"))
            )
            self.assertEqual(signed_text, SIGNATURE_LONG_TEXT)

        def test_verify_short_message(self):
            self.assertEqual(
                self.make_key().verify(
                    MESSAGE_TEXT_SHORT.encode("utf-8"),
                    AbstractTests.TestRSA.from_base64(SIGNATURE_SHORT_TEXT),
                ),
                True,
            )
            self.assertEqual(
                self.make_key().verify(
                    MESSAGE_TEXT_SHORT.encode("utf-8"), b"wrong signature"
                ),
                False,
            )

        def test_verify_long_message(self):
            self.assertEqual(
                self.make_key().verify(
                    MESSAGE_TEXT_LONG.encode("utf-8"),
                    AbstractTests.TestRSA.from_base64(SIGNATURE_LONG_TEXT),
                ),
                True,
            )
            self.assertEqual(
                self.make_key().verify(
                    MESSAGE_TEXT_LONG.encode("utf-8"), b"wrong signature"
                ),
                False,
            )

        def test_sign_too_big(self):
            self.assertRaises(ValueError, self.make_key().sign, b"a" * 1000)

        def test_verify_too_big(self):
            self.assertRaises(
                ValueError, self.make_key().verify, b"a" * 1000, b"a" * 1000
            )

        def test_make_from_key(self):

            key = self.get_key_implementation()(key=ExampleKey())
            self.assertEqual(key.e, PRIVATE_KEY_E)
            self.assertEqual(key.n, PRIVATE_KEY_N)
            self.assertEqual(key.d, PRIVATE_KEY_D)
            self.assertEqual(key.p, PRIVATE_KEY_P)
            self.assertEqual(key.q, PRIVATE_KEY_Q)
            self.assertEqual(key.u, PRIVATE_KEY_U)

        def test_setters_values(self):

            key = self.get_key_implementation()(0, 0, 0, 0, 0, 0)
            key.e = 1
            key.n = 2
            key.d = 3
            key.p = 4
            key.q = 5
            key.u = 6
            self.assertEqual(key.e, 1)
            self.assertEqual(key.n, 2)
            self.assertEqual(key.d, 3)
            self.assertEqual(key.p, 4)
            self.assertEqual(key.q, 5)
            self.assertEqual(key.u, 6)

        def test_setters_none(self):

            key = self.get_key_implementation()(0, 0, 0, 0, 0, 0)
            key.e = None
            key.n = None
            key.d = None
            key.p = None
            key.q = None
            key.u = None
            self.assertEqual(key.e, None)
            self.assertEqual(key.n, None)
            self.assertEqual(key.d, None)
            self.assertEqual(key.p, None)
            self.assertEqual(key.q, None)
            self.assertEqual(key.u, None)

        @typing.no_type_check
        def test_setters_invalid(self):

            # Turn off type checking since we need to pass
            # invalid values on purpose
            key = self.get_key_implementation()(0, 0, 0, 0, 0, 0)
            with self.assertRaises(TypeError):
                key.e = "test"
            with self.assertRaises(TypeError):
                key.e = "test"
            with self.assertRaises(TypeError):
                key.n = "test"
            with self.assertRaises(TypeError):
                key.d = "test"
            with self.assertRaises(TypeError):
                key.p = "test"
            with self.assertRaises(TypeError):
                key.q = "test"
            with self.assertRaises(TypeError):
                key.u = "test"
