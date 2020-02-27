using System;
using System.ComponentModel;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
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
        
        public MainPage()
        {
            InitializeComponent();
        }

        //Based on https://codereview.stackexchange.com/questions/110952/bouncycastle-diffie-hellman
        void Button_Clicked(System.Object sender, System.EventArgs e)
        {
            //BEGIN SETUP ALICE
            IAsymmetricCipherKeyPairGenerator aliceKeyGen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            DHParametersGenerator aliceGenerator = new DHParametersGenerator();
            aliceGenerator.Init(EcdhKeyBitSize, EcdhDefaultPrimeProbability, new SecureRandom());
            DHParameters aliceParameters = aliceGenerator.GenerateParameters();

            KeyGenerationParameters aliceKGP = new DHKeyGenerationParameters(new SecureRandom(), aliceParameters);
            aliceKeyGen.Init(aliceKGP);

            AsymmetricCipherKeyPair aliceKeyPair = aliceKeyGen.GenerateKeyPair();
            IBasicAgreement aliceKeyAgree = AgreementUtilities.GetBasicAgreement(EcdhAlgorithm);
            aliceKeyAgree.Init(aliceKeyPair.Private);

            //END SETUP ALICE

            /////AT THIS POINT, Alice's Public Key, Alice's Parameter P and Alice's Parameter G are sent unsecure to BOB

            //BEGIN SETUP BOB
            IAsymmetricCipherKeyPairGenerator bobKeyGen = GeneratorUtilities.GetKeyPairGenerator(EcdhAlgorithm);
            DHParameters bobParameters = new DHParameters(aliceParameters.P, aliceParameters.G);

            KeyGenerationParameters bobKGP = new DHKeyGenerationParameters(new SecureRandom(), bobParameters);
            bobKeyGen.Init(bobKGP);

            AsymmetricCipherKeyPair bobKeyPair = bobKeyGen.GenerateKeyPair();
            IBasicAgreement bobKeyAgree = AgreementUtilities.GetBasicAgreement(EcdhAlgorithm);
            bobKeyAgree.Init(bobKeyPair.Private);
            //END SETUP BOB

            BigInteger aliceAgree = aliceKeyAgree.CalculateAgreement(bobKeyPair.Public);
            BigInteger bobAgree = bobKeyAgree.CalculateAgreement(aliceKeyPair.Public);

            if (!aliceAgree.Equals(bobAgree))
            {
                throw new Exception("Keys do not match.");
            }

            KeyParameter aliceSharedKey = new KeyParameter(aliceAgree.ToByteArrayUnsigned());
            KeyParameter bobSharedKey = new KeyParameter(bobAgree.ToByteArrayUnsigned());

            Console.WriteLine($"ALICE SHARED KEY:{Convert.ToBase64String(aliceSharedKey.GetKey())}");
            Console.WriteLine($"BOB SHARED KEY:{Convert.ToBase64String(bobSharedKey.GetKey())}");
        }
    }
}
