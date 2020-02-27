using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xamarin.Forms;

namespace Xamarin.Ecdh
{
    // Learn more about making custom code visible in the Xamarin.Forms previewer
    // by visiting https://aka.ms/xamarinforms-previewer
    [DesignTimeVisible(false)]
    public partial class MainPage : ContentPage
    {
        public MainPage()
        {
            InitializeComponent();
        }

        void Button_Clicked(System.Object sender, System.EventArgs e)
        {
            Console.WriteLine($"Button {sender} was pressed.");

            using (ECDiffieHellmanCng dhBob = new ECDiffieHellmanCng())
            {
                dhBob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                dhBob.HashAlgorithm = CngAlgorithm.Sha256;
                string xmlBob = Crypto.ToXmlString(dhBob.PublicKey);

                Console.WriteLine(xmlBob);

                using (ECDiffieHellmanCng dhAlice = new ECDiffieHellmanCng())
                {
                    dhAlice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                    dhAlice.HashAlgorithm = CngAlgorithm.Sha256;
                    ECDiffieHellmanPublicKey keyBob = Crypto.FromXmlString(xmlBob, dhAlice.KeySize);
                    byte[] b = dhAlice.DeriveKeyMaterial(keyBob);


                    string xmlAlice = Crypto.ToXmlString(dhAlice.PublicKey);
                    ECDiffieHellmanPublicKey keyAlice = Crypto.FromXmlString(xmlAlice, dhBob.KeySize);
                    byte[] b2 = dhBob.DeriveKeyMaterial(keyAlice);

                    Console.WriteLine(b.SequenceEqual(b2));
                }
            }
        }
    }
}
