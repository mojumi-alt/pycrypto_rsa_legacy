import unittest
import base64
import typing
from pycrypto_rsa_legacy import import_key

PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
"""

PRIVATE_KEY_E = 65537
PRIVATE_KEY_N = 713777003443624254070028244562591187187365446935302550090163819831331237424631142520358964229023802505961806210205062610314265486864690456849690318683230443440330623729773123441324770464589709695050488345513467072139936054385394798234134505423113774259770121393470617291570223904812540031690265197520827836514261606168140252951971959019121875459386395000057646827379443214756649084797463941282909962101929938591177547888186256812118874843532032727355712278848963109500884789638634981237889616092756787714496879257071765124732318410862484859363491515987909632236246974983168072236058457776422012285280417177808495601802164306793437270087463466618159798190988371609088537964147214989300633655507213165017947363270554979664956917291274023575845506290838231703484823502397543805146092188109702083022159662210044001241456054740445176283288320777267057159651900717627170510085410563055432942123474578377279299502562217534233436541552834960956483031952108235540283854286619840165115349830959466937863086176989733014915260063212204370035344517758095127889238254660033754100003354181226451956900003838476514424626870474749180359473253897966722827048069074403062152435534879159853636059906721871753111711440819277476837709254282748988026049137
PRIVATE_KEY_D = 290343229722170028794815874356040666549191781239982956674529383264011837479355620685704097653225369472285622028087212743901351091468671903564817879375267387528480918148529179108908805612558780168538435441946850816220493542668005054072122231912081397548012295057262866030903532568876285128016462986833528981792200482598125744744497680234238071882052156966431737460483313043633216803135224262305117036554836188228525972509837394559193600943227469894291961117928728551118136887019264700052341125327811111666492440234900096900646604366327075585140327426933849412255214458742218686447426101234916859400142637004052791247680075843121831208842050316083220173833666065273030915104487306961000346744385280918552386732681262236976196248034786625421816968159008449414605589095794866161857594248540312945104322134607369342353982073451377779919914972780477893191982094008005975446417242645139174681404330484475985394262232751832694297712235619717504141726925014089527565281598378751721910336141152597028284636998542338958376130170663424758530247521865709052056220688227049218657388329992028907734100669170974391666563559703093762074268163286669243450756077684585170757200843831053486770852165461353561247290353350962948956426750635115027677665691
PRIVATE_KEY_P = 23816042538162119303929459139372945368495251290365090582679386051249393794640635944977980851572436119061262703809450367960101657644142470991253862781143877315561279780395338896095946730123209241307614261861221298470680825584276637908625092046615962655393173831067363584838867619645216016956797402294988425003791406000712034047015793372115573842711228076205050772742710642564027091375354266834680519027710160456322362683303670554765499836790879469304811403415268897679232442151894954846146014574802780196872926467534575527065219890861709633261221662340269780558157061718009093566130304927277494599975919855416422392023
PRIVATE_KEY_Q = 29970428642789379495522620298487866287730364732376613043347355681751008242929403127005183260587520618965606042449852199222112599992910410850648107501038420183541293294989097718752761322440261824852988663566511401018659314645916139523250283547591375049701452132911373703170699313474353554550418195704789352398395530300302256575105129748531972390924831970588388087425187596193604914471779350182894438955686267767275754239484228420129063727082496196637596475300811408539169313268322891361905429215712257766692357465188708695702748532167181582524775465042388495622597875892501132624073852045163960122990448212191596860919
PRIVATE_KEY_U = 21374600776186700814222619088769733901001107322324450272015624413214205105725122306190379309463476051177628424522444883322156746395582715479444099292390688604690759890332133714453850607085741358210479105802121472134513606772765581463236316062230479780845839407329114522523814922074709975618847308324583584651298994861809403915761127702678356175676530499740779787403148888480427593629288732335269608083490166493328874504069931304194133654637718246232496414847857390205166582145131787882064194779231218306349245411340387117246819463941464055070709915885777219025391291270074796478228722971353887322701716743622909766736

MESSAGE_TEXT_SHORT = "TEST 1 2 3 5"
CIPHER_TEXT_SHORT = "VkOb5o2NoOLcRQrbBU/qynv4nBPBzJ50kKW63T4qIpLMZIM12p2eAvXV9/JdzrhbyWY9sIkiHnWSk3vlZkNWN1FUQIVfj9otSCHhMILmhrPUuX0DEElNaTV5JY42gbBUemoJN9C0c1KxIHfH+/GqjZTksNGZSzbJDecm1rTGCOveFAb3w1+//azmG5DAmcIHPK6usOJ9gU/owVYgF8RzOU93Uymvdf5xuiv1HFBW1MfyGVNVqkbvEGK8D+4wJzUe/VU7QQOKUtvwMWQkrngj6RABaNCGAgHRPgm3YciVnoIVLhKql+ZKjPBQyfUQ74nlKQu3KkvBusGFNGNJNQuZOvLksyrEUa4xCK3Y7cieJLjBGnfenjGYRD3cqe0itiqjnPZmav42+ArQhnp0QlmIayeJwCXdZFX4xVdkf4MDbVb8z6rEgu3E9zTxlzyyxNh2kZhhjr3PXe0Ml68VOlWuw6DGmmpl7DLLn1UGmrqvibRB6JRzVmKgndiM0Rrn+23CDEtVdJQaNdyhFoyPs4UNUOIziG5m57DNh5xhjwTSSP/efKSq/O9DIV1i9hO+We+zVBZMYO8b/7/ivEQsISENiF3R6A4BYgY4ucQlcB7B3qPCSGCTU9Wb73kgq2l66wmd7BzAZ1ZsWQSy6TwlcyAWmtzrGrqCL7mKio1zJPZog3A="
SIGNATURE_SHORT_TEXT = "mFDz3rUaobc2FBVaxHll5tdmR0FNjfqcGXlla3+ZS+KUjknhmqXtzYsLcYbNRon3bTN98Fo1mtlLUS6V6923MBsGTaltPnpD1ZxG4/aUDhv4/Ujcxk1MFxOBZUGazBzg46xrPNNrfyCNQJF4fghXiR/heLZBDlGOKIOZF/vFTlEv/cdhZwWNzkr52Rty0/gZ0q0cSFKroZYenwwZX0HmGkBPq57t6WCAz0Qo+QKzBe5cxnpJD2QHrMqQ4zPZqkJywQ15PxZI+YnwTJdxCLLGlP16hIXikgknDhF7/bc343tq+Z0J3RhHbEpP/JnSpY2Adr+f1ZUFvknQ3MfovmvQ/Zi/WBSjOy+2gi5S25kGRtOqPcDhz/ZvkHvJe8uaKbiHoYmvO6Xws6AfTO+zBT07BO+76SfsK9c2QLUKDx+VUvbqRKPjx3SIBcyJdgEnnAHptrb4CrTVHYZTYbU8Wjwfai4ggJhHWO4TdmrJneZnJf1ajs0Kl5/9GxGx/nR9SO7YRMPrJ5wKZrOYPs3EFpFfF4UMOFIWJAGk8YjQRSUo2sg0HWh6MPAYiUqHYyGNogxqTRTqw4GUB9M0dx+3TcYGneBtNzGusBvs2ZKFUYam5Fx0TDLXtkDy/EpxpD25mAjER8deD6FCcai7qJOG4CqtjugQBjYa9TAvLwQCpKfW4to="

MESSAGE_TEXT_LONG = "Some slighty longer text that still does not overflow"
CIPHER_TEXT_LONG = "Vg2oZE+pM4DwUSm/GmUvAzQdhU6jJyOfUWAefum4bqiSNtQn8wNnb+l3OBn9OpM5tBYBDIppPOsM0u2OHR5vlMfbQAHaFANMmBmFwTeNWnOFavn0e0xNeB7n+C4yB6KXVMvyqv3z427YLge7SFDl+XtmK7rRF9WpWnRaMti7sA+jSsLlO7jntU0leBIomEg/Eblwl6qm1U/JW7DcYfrI1NSRlNPJxJJoS6GHC2lVIfBkzFjYJ+X4biyP6FKBF58S8zFCmt+hET/Q6+Ty+JAjCTspFk2wGnnOWqliLOUj9NI4zDwY8X64mmfR65h72DobBJ+tZeltsV0yN1q82M0VwdQOm+d6XAIqKU5UQYDYpRLa8CYv91WVVUcVFw1Mm+PZ2MlbYHPYTxr3b0cLOvBjKB32UTrGO6nVKW0Si9UwaljPXHoo9IQMrZTI9h6A8G4+0rh2liGikGrEGKgSpV+iK1JWIYl3gJOiS03OypsPCJH9Io4IRFPZlffYwbsv1xl2tz9d+9sJjAW3aIz2ll+KtdHF9zOk2IXBU9LhXnffBgbYOgPlg88vOhtSzVI9pqjn6SzL5+kpr5gXskQ7HVibmcN40sRlNBSN6yUzrvYuxQOtHr5ROyHhbJzjxfDK3tJUD0Rpi27OfwK1fXvQIoU+rkBDnvRujC9DV3hAaUumAes="
SIGNATURE_LONG_TEXT = "FCyKIf4kla2m9nMqXWU4Wfvb/cltR8BSOpomGRAElpeLW6i2WiGQ/u8kOvxtjB0qRwZ0zrJhcCky/7TSIBeEtGOH5JzeyEZ3L/LrIOqJGIjIpbC9NeIUOnrCtZLUaS7sfbl+p5CCdQdUTgD9YYcSgOEO3t8bhebsvNkBVuiX8ZFIjQ26Tmav9voRB5iQJ3XvYvpQrnSztmIrgKRXvXwLLUiISRXUyduc+LIGsJGwOYQI95eHrZV5oY4JL+KWjY0+vcRM9cWimrjgDZIvLqICU2hmxb5Ct5HUaGfxmj4sGlQ+Ga/aI8GCva8eiYaEyb8IFQaPiZnuA5cTMWbmY6STBTTZvgCvNmt+PAF6s+ZbO8dCIyivMRGsFtDfQEsEM6MbFivUWtOK5eek6DizxsjAcGiN2RCXSk8mx6RGZILecmxkg71jKnX635ILLOPrYaCN8IxyrzSsUgtoYm6Wmkn7iWRQw0dDCOHvUOQwOIIGVXki3x1zny9vPE//Rb7cKmivwR2SjS+Lyx4bmS1m72bAZck8DBFUpACQcQ5fQu3UNxo4rnnsCJuSNVwyS6jOm7CCzyjhB4L9pGdjLj9yIL9ITWevP2Tws9mYHfmWhQyBLJVjvcYPkEzysUdLWsV6EUSo1ly2SwNI14+aazLZFljoHDRnkjQ/OPhhALUcnEhf//4="

MAX_MESSAGE_LENGTH = 4095


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

        def test_import_key(self):

            key = import_key(PRIVATE_KEY)
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
