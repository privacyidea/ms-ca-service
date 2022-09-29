using CERTADMINLib;
using CERTCLILib;
using CERTENROLLLib;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Policy;

namespace CAService
{
    class CertOperations
    {
        private const int CC_DEFAULTCONFIG = 0;
        private const int CC_UIPICKCONFIG = 0x1;
        private const int CR_IN_BASE64HEADER = 0x0;
        private const int CR_IN_BASE64 = 0x1;
        private const int CR_IN_FORMATANY = 0;
        private const int CR_IN_PKCS10 = 0x100;
        private const int CR_DISP_ISSUED = 0x3;
        private const int CR_DISP_UNDER_SUBMISSION = 0x5;
        private const int CR_OUT_BASE64 = 0x1;
        private const int CR_OUT_CHAIN = 0x100;

        public const int CRL_REASON_UNSPECIFIED = 0;
        public const int CRL_REASON_KEY_COMPROMISE = 1;
        public const int CRL_REASON_CA_COMPROMISE = 2;
        public const int CRL_REASON_AFFILIATION_CHANGED = 3;
        public const int CRL_REASON_SUPERSEDED = 4;
        public const int CRL_REASON_CESSATION_OF_OPERATION = 5;
        public const int CRL_REASON_CERTIFICATE_HOLD = 6;

        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ce5b7072-ba61-43ec-8a39-8c4f94e982de
        public const int CA_DISP_INCOMPLETE = 0x00;
        public const int CA_DISP_ERROR = 0x01;
        public const int CA_DISP_REVOKED = 0x02;
        public const int CA_DISP_VALID = 0x03;
        public const int CA_DISP_INVALID = 0x04;

        private readonly ILogger<PrivacyIDEACAService> _logger;

        public CertOperations(ILogger<PrivacyIDEACAService> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Return the disposition of a CertificateRequest. If the id is given, it takes precedence over the serial.
        /// Either the requestId or the certSerial have to be given, throws IllegalOperationException otherwise.
        /// </summary>
        /// <param name="requestId"></param>
        /// <param name="certSerial"></param>
        /// <param name="caName"></param>
        /// <returns>The disposition</returns>
        /// <exception cref="COMException">COM call failure</exception>
        public int GetRequestStatus(int? requestId, string? certSerial, string caName)
        {
            if (requestId is null && certSerial is null)
            {
                throw new ArgumentException("Either requestId or certSerial are required");
            }

            if (requestId is not null)
            {
                certSerial = null;
            }

            var objCertRequest = new CCertRequest();
            var dispo = objCertRequest.RetrievePending((int)requestId!, caName);
            return dispo;
        }

        public int GetCertificateValidity(string caName, string serialNumber)
        {
            CCertAdmin certAdmin = new();
            return certAdmin.IsValidCertificate(caName, serialNumber);
        }

        public string? GetDispositionMessage()
        {
            var ccertreq = new CCertRequest();
            var msg = ccertreq.GetDispositionMessage();
            return msg;
        }

        private string CreateEOBOCMCRequest(string csr)
        {
            var objPkcs10 = new CX509CertificateRequestPkcs10();
            objPkcs10.InitializeDecode(csr, EncodingType.XCN_CRYPT_STRING_BASE64_ANY);

            CX509CertificateRequestCmc objCmc = new CX509CertificateRequestCmc();
            objCmc.InitializeFromInnerRequest(objPkcs10);
            // The requester name is extracted from the original CSR, cuts off after the "," if there is OU= etc appended
            string tmp = objPkcs10.Subject.Name.Replace("CN=", "");
            string requesterName = tmp;
            if (requesterName.IndexOf(",") != -1)
            {
                requesterName = tmp[..tmp.IndexOf(",")].TrimEnd();
            }
            _logger.LogInformation($"Requester Name from CSR: {requesterName}");
            objCmc.RequesterName = requesterName;

            // Get the signer certificate for the container and create the request
            CSignerCertificate signer = new();
            X509Certificate2? cert = null;
            string? requestStr;
            try
            {
                // TODO get cert from store??
                cert = new X509Certificate2("C:\\enrollment_cert.pfx", "passw0rd");
                // temporarily add this cert to the local user store so we can sign the request
                var store = new X509Store(StoreName.My);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);

                signer.Initialize(false, X509PrivateKeyVerify.VerifyNone, EncodingType.XCN_CRYPT_STRING_HEXRAW, cert.Thumbprint);
                objCmc.SignerCertificate = signer;
                objCmc.Encode();
                requestStr = objCmc.RawData;

                store.Remove(cert);
                store.Close();
            }
            finally
            {
                if (cert != null)
                {
                    // This method can be used to reset the state of the certificate. It also frees any resources associated with the certificate.
                    cert.Reset();
                    cert = null;
                }
            }

            //_logger.LogInformation($"EOBO data:\n{requestStr}");
            return requestStr;
        }

        private static IX509PrivateKey CreatePrivateKey(bool machineContext)
        {
            var cspInfo = new CCspInformations();
            cspInfo.AddAvailableCsps();

            var privateKey = new CX509PrivateKey
            {
                Length = 2048,
                KeySpec = X509KeySpec.XCN_AT_SIGNATURE,
                KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES,
                MachineContext = machineContext,
                ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG,
                CspInformations = cspInfo
            };
            privateKey.Create();

            return privateKey;
        }

        public static string ConvertToPEM(string privKeyStr)
        {
            var rsa = new RSACryptoServiceProvider();
            var cryptoKey = Convert.FromBase64String(privKeyStr);
            rsa.ImportCspBlob(cryptoKey);

            return ExportPrivateKey(rsa);
        }

        // from https://stackoverflow.com/a/23739932
        //    internal helper used to convert a RSA key to a PEM string
        private static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            TextWriter outputStream = new StringWriter();

            var parameters = csp.ExportParameters(true);

            using var stream = new MemoryStream();
            var writer = new BinaryWriter(stream);
            writer.Write((byte)0x30); // SEQUENCE
            using (var innerStream = new MemoryStream())
            {
                var innerWriter = new BinaryWriter(innerStream);
                EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                EncodeIntegerBigEndian(innerWriter, parameters.D);
                EncodeIntegerBigEndian(innerWriter, parameters.P);
                EncodeIntegerBigEndian(innerWriter, parameters.Q);
                EncodeIntegerBigEndian(innerWriter, parameters.DP);
                EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                var length = (int)innerStream.Length;
                EncodeLength(writer, length);
                writer.Write(innerStream.GetBuffer(), 0, length);
            }

            var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
            outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");

            // Output as Base64 with lines chopped at 64 characters
            for (var i = 0; i < base64.Length; i += 64)
            {
                outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
            }
            outputStream.WriteLine("-----END RSA PRIVATE KEY-----");

            return outputStream.ToString() ?? "";
        }

        // from https://stackoverflow.com/a/23739932
        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> 8 * i & 0xff));
                }
            }
        }

        // from https://stackoverflow.com/a/23739932
        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        internal void RevokeCertificate(string caName, string serialNumber, int reason, DateTime revocationTime)
        {
            CCertAdmin certAdmin = new();
            certAdmin.RevokeCertificate(caName, serialNumber, reason, revocationTime);
        }

        /// <summary>
        /// Submit the CertificateRequest to the speficed CA.
        /// </summary>
        /// <param name="caName">Name of the CA (e.g. dc.company.local\Main-DC-CA)</param>
        /// <param name="certificateRequest">Base64 encoded certificate request</param>
        /// <param name="templateName">Template name</param>
        /// <returns>result of the submission as <see cref="CertSubmissionResult"/></returns>
        /// <exception cref="COMException">COM call failure</exception>
        public CertSubmissionResult SendCertificateRequest(string caName, string certificateRequest, string templateName = "")
        {
            _logger.LogInformation($"Sending\n{certificateRequest}\n to CA={caName}, templateName={templateName}");
            var objCertRequest = new CCertRequest();
            int disposition = 0;
            string attributes = "";

            if (!string.IsNullOrEmpty(templateName))
            {
                attributes = "CertificateTemplate:" + templateName;
            }

            // Convert the originial CSR to a EOBO CMC request which will contain the CN from the CSR as requester
            // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/cmc-eobo-request
            string actualCSR = CreateEOBOCMCRequest(certificateRequest);

            disposition = objCertRequest.Submit(CR_IN_BASE64 | CR_IN_FORMATANY, actualCSR, attributes, caName);
            string dispositionMessage = objCertRequest.GetDispositionMessage();

            _logger.LogInformation("Disposition: {disposition}", disposition);
            _logger.LogInformation("Disposition Message: {dispositionMessage}", dispositionMessage);

            uint lastStatus = (uint)objCertRequest.GetLastStatus();
            _logger.LogInformation("Disposition Message: {lastStatus}", lastStatus);
            /*switch (disposition)
            {
                case CR_DISP_ISSUED:
                    _logger.LogInformation("CA Response: The certificate had been issued.");
                    break;
                case CR_DISP_UNDER_SUBMISSION:
                    _logger.LogInformation("CA Response: The certificate is still pending.");
                    break;
                default:
                    _logger.LogInformation("CA Response: The submission failed: {0}", dispositionMessage);
                    _logger.LogInformation("Last status: 0x{0:X}", lastStatus);
                    break;
            }
            */
            CertSubmissionResult res = new(disposition, dispositionMessage, objCertRequest.GetRequestId(), lastStatus);

            return res;
        }

        public int? GetRequestId()
        {
            var objCertRequest = new CCertRequest();
            var ret = objCertRequest.GetRequestId();
            _logger.LogInformation($"GetRequestId returned {ret}");
            return null;
        }

        /// <summary>
        /// Retrieve the certificate from the CA. The requestId that was given when submitting the CertificateRequest is required for this.
        /// </summary>
        /// <param name="caName">Name of the CA (e.g. dc.company.local\Main-DC-CA)</param>
        /// <param name="requestId">requestId</param>
        /// <returns>The certificate or null if error</returns>
        /// <exception cref="COMException">COM call failure</exception>
        public string? DownloadCert(string caName, int requestId)
        {
            _logger.LogInformation($"Downloading Cert for requestID={requestId} from CA={caName}");
            TextWriter s = new StringWriter();

            var objCertRequest = new CCertRequest();
            // Check the dispositon before requesting the cert
            var iDisposition = objCertRequest.RetrievePending(requestId, caName);
            if (iDisposition == CR_DISP_ISSUED)
            {
                var cert = objCertRequest.GetCertificate(CR_OUT_BASE64);

                s.WriteLine("-----BEGIN CERTIFICATE-----");
                s.Write(cert);
                s.WriteLine("-----END CERTIFICATE-----");
                return s.ToString();
            }
            return null;
        }

        // gets the current distinguished name of the current user context
        /*private static string GetCurrentUserDN()
        {
            return UserPrincipal.Current.DistinguishedName.Replace(",", ", ");
        }*/

        // gets the current distinguished name of the current computer
        private static string GetCurrentComputerDN()
        {
            return $"CN={System.Net.Dns.GetHostEntry("").HostName}";
        }
    }
}