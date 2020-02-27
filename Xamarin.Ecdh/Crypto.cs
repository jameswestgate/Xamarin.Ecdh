using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Xamarin.Ecdh
{
    //https://stackoverflow.com/questions/52800998/net-ecdiffiehellmancng-and-bouncycastle-core-compatible-agreement
    public class Crypto
    {

        public static string ToXmlString(ECDiffieHellmanPublicKey key)
        {
            // the regular ToXmlString from ECDiffieHellmanPublicKey throws PlatformNotSupportedException on .net core 2.1
            ECParameters parameters = key.ExportParameters();
            return string.Format("<ECDHKeyValue xmlns='http://www.w3.org/2001/04/xmldsig-more#'><DomainParameters><NamedCurve URN='urn:oid:{0}' />" +
                                 "</DomainParameters><PublicKey><X Value='{1}' xsi:type='PrimeFieldElemType' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' />" +
                                 "<Y Value='{2}' xsi:type='PrimeFieldElemType' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' /></PublicKey></ECDHKeyValue>",
                GetOid(parameters.Curve),
                new BigInteger(parameters.Q.X.Reverse().ToArray().Concat(new byte[] { 0 }).ToArray()).ToString(System.Globalization.CultureInfo.InvariantCulture), // watch out for big endian - little endian
                new BigInteger(parameters.Q.Y.Reverse().ToArray().Concat(new byte[] { 0 }).ToArray()).ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        // The regular FromXmlString from ECDiffieHellmanPublicKey throws PlatformNotSupportedException on .net core 2.1
        public static ECDiffieHellmanPublicKey FromXmlString(string xml, int keySize)
        {
            XDocument doc = XDocument.Parse(xml);
            XNamespace nsSys = "http://www.w3.org/2001/04/xmldsig-more#";
            string xString = doc.Element(nsSys + "ECDHKeyValue").Element(nsSys + "PublicKey").Element(nsSys + "X").Attribute("Value").Value;
            string yString = doc.Element(nsSys + "ECDHKeyValue").Element(nsSys + "PublicKey").Element(nsSys + "Y").Attribute("Value").Value;
            string curve = doc.Element(nsSys + "ECDHKeyValue").Element(nsSys + "DomainParameters").Element(nsSys + "NamedCurve").Attribute("URN").Value;
            curve = curve.Replace("urn:", "").Replace("oid:", "");

            byte[] arrayX = BigInteger.Parse(xString, System.Globalization.CultureInfo.InvariantCulture).ToByteArray(false, true); // watch out for big endian - little endian
            byte[] arrayY = BigInteger.Parse(yString, System.Globalization.CultureInfo.InvariantCulture).ToByteArray(false, true);

            // make sure each part has the correct and same size
            int partSize = (int)Math.Ceiling(keySize / 8.0);
            ResizeRight(ref arrayX, partSize);
            ResizeRight(ref arrayY, partSize);

            ECParameters parameters = new ECParameters() { Q = new ECPoint() { X = arrayX, Y = arrayY }, Curve = GetCurveByOid(curve) };
            ECDiffieHellman dh = ECDiffieHellman.Create(parameters);
            return dh.PublicKey;
        }

        private static void ResizeRight(ref byte[] b, int length)
        {
            if (b.Length == length) return;
            if (b.Length > length) throw new NotSupportedException();

            byte[] newB = new byte[length];
            Array.Copy(b, 0, newB, length - b.Length, b.Length);
            b = newB;
        }

        private static ECCurve GetCurveByOid(string oidValue)
        {
            // there are strange bugs in .net core 2.1 where the createfromvalue doesn't work for the named curves
            switch (oidValue)
            {
                case "1.2.840.10045.3.1.7":
                    return ECCurve.NamedCurves.nistP256;
                case "1.3.132.0.34":
                    return ECCurve.NamedCurves.nistP384;
                case "1.3.132.0.35":
                    return ECCurve.NamedCurves.nistP521;
                default:
                    return ECCurve.CreateFromValue(oidValue);
            }
        }

        private static string GetOid(ECCurve curve)
        {
            // there are strange bugs in .net core 2.1 where the value of the oid of the named curves is empty
            if (curve.Oid.FriendlyName == ECCurve.NamedCurves.nistP256.Oid.FriendlyName)
                return "1.2.840.10045.3.1.7";
            else if (curve.Oid.FriendlyName == ECCurve.NamedCurves.nistP384.Oid.FriendlyName)
                return "1.3.132.0.34";
            else if (curve.Oid.FriendlyName == ECCurve.NamedCurves.nistP521.Oid.FriendlyName)
                return "1.3.132.0.35";
            else
                return curve.Oid.Value;
        }
    }
}
