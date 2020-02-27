using System;
using System.ComponentModel;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Xamarin.Forms;

namespace Xamarin.Ecdh
{
    // Learn more about making custom code visible in the Xamarin.Forms previewer
    // by visiting https://aka.ms/xamarinforms-previewer
    [DesignTimeVisible(false)]
    public partial class MainPage : ContentPage
    {
        const string EcdhAlgorithm = "ECDH"; //What do you think about the other algorithms?
        const int EcdhKeyBitSize = 256;
        const int EcdhDefaultPrimeProbability = 30;


        private IBasicAgreement _aliceKeyAgree;

        public MainPage()
        {
            InitializeComponent();
        }

        //Based on https://codereview.stackexchange.com/questions/110952/bouncycastle-diffie-hellman
        void Button_Clicked(System.Object sender, System.EventArgs e)
        {
            try
            {
                // Setup Alice's parameters and return the public information in base64 format
                var aliceValues = SetupAlice();

                if (!aliceValues.StartsWith("ECDH:")) throw new ApplicationException("Public Keys Values supplied are not in a valid format.");
                var splits = (aliceValues.Substring(5).Split(","));
                var aliceP = new BigInteger(Convert.FromBase64String(splits[0]));
                var aliceG = new BigInteger(Convert.FromBase64String(splits[1]));

                var publicKeyDerRestored = Convert.FromBase64String(splits[2]);
                var alicePbk = PublicKeyFactory.CreateKey(publicKeyDerRestored);

                /////AT THIS POINT, Alice's Public Key, Alice's Parameter P and Alice's Parameter G are sent unsecure to BOB

                //BEGIN SETUP BOB
                IAsymmetricCipherKeyPairGenerator bobKeyGen = GeneratorUtilities.GetKeyPairGenerator(EcdhAlgorithm);
                DHParameters bobParameters = new DHParameters(aliceP, aliceG);

                KeyGenerationParameters bobKGP = new DHKeyGenerationParameters(new SecureRandom(), bobParameters);
                bobKeyGen.Init(bobKGP);

                AsymmetricCipherKeyPair bobKeyPair = bobKeyGen.GenerateKeyPair();
                IBasicAgreement bobKeyAgree = AgreementUtilities.GetBasicAgreement(EcdhAlgorithm);
                bobKeyAgree.Init(bobKeyPair.Private);
                //END SETUP BOB

                //Alice and Bob can individually calculate a shared key
                BigInteger aliceAgree = _aliceKeyAgree.CalculateAgreement(bobKeyPair.Public);
                BigInteger bobAgree = bobKeyAgree.CalculateAgreement(alicePbk);

                if (!aliceAgree.Equals(bobAgree))
                {
                    throw new Exception("Keys do not match.");
                }

                KeyParameter aliceSharedKey = new KeyParameter(aliceAgree.ToByteArrayUnsigned());
                KeyParameter bobSharedKey = new KeyParameter(bobAgree.ToByteArrayUnsigned());

                Console.WriteLine($"ALICE SHARED KEY:{Convert.ToBase64String(aliceSharedKey.GetKey())}");
                Console.WriteLine($"BOB SHARED KEY:{Convert.ToBase64String(bobSharedKey.GetKey())}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"EXCEPTION: {ex}");
            }
        }

        private string SetupAlice()
        {
            IAsymmetricCipherKeyPairGenerator aliceKeyGen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            DHParametersGenerator aliceGenerator = new DHParametersGenerator();
            aliceGenerator.Init(EcdhKeyBitSize, EcdhDefaultPrimeProbability, new SecureRandom());
            DHParameters aliceParameters = aliceGenerator.GenerateParameters();

            KeyGenerationParameters aliceKGP = new DHKeyGenerationParameters(new SecureRandom(), aliceParameters);
            aliceKeyGen.Init(aliceKGP);

            //Alice keeps the key agreement variable in memory for now
            AsymmetricCipherKeyPair aliceKeyPair = aliceKeyGen.GenerateKeyPair();
            _aliceKeyAgree = AgreementUtilities.GetBasicAgreement(EcdhAlgorithm);
            _aliceKeyAgree.Init(aliceKeyPair.Private);

            var tuple1 = Convert.ToBase64String(aliceParameters.P.ToByteArray());
            var tuple2 = Convert.ToBase64String(aliceParameters.G.ToByteArray());

            //Restore as Bigintegers like so
            //var pRestore = new BigInteger(tuple1);

            byte[] publicKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(aliceKeyPair.Public).GetDerEncoded();
            var tuple3 = Convert.ToBase64String(publicKeyDer);

            //https://stackoverflow.com/questions/55976529/how-to-convert-rsa-public-key-to-string-using-bouncycastle-c-sharp
            //Restore the Public Key like this
            //byte[] publicKeyDerRestored = Convert.FromBase64String(tuple3);
            //var temp = PublicKeyFactory.CreateKey(publicKeyDerRestored);

            return $"ECDH:{tuple1},{tuple2},{tuple3}";
        }
    }
}
