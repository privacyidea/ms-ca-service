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

        private readonly LogWrapper _logger;

        public CertOperations(LogWrapper logger)
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

        private string? CreateEOBOCMCRequest(string csr)
        {
            var objPkcs10 = new CX509CertificateRequestPkcs10();
            objPkcs10.InitializeDecode(csr, EncodingType.XCN_CRYPT_STRING_BASE64_ANY);

            var objCmc = new CX509CertificateRequestCmc();
            objCmc.InitializeFromInnerRequest(objPkcs10);
            // The requester name is extracted from the original CSR, cuts off after the "," if there is OU= etc appended
            string tmp = objPkcs10.Subject.Name.Replace("CN=", "");
            string requesterName = tmp;
            if (requesterName.IndexOf(",") != -1)
            {
                requesterName = tmp[..tmp.IndexOf(",")].TrimEnd();
            }
            _logger.Log($"Requester Name from CSR: {requesterName}");
            objCmc.RequesterName = requesterName;

            // Get the signer certificate for the container and create the request
            CSignerCertificate signer = new();
            string? requestStr = null;
            if (Settings.GetString("enrollment_agent_cert_thumbprint", _logger) is string s)
            {
                signer.Initialize(true, X509PrivateKeyVerify.VerifyNone, EncodingType.XCN_CRYPT_STRING_HEXRAW, s);
                objCmc.SignerCertificate = signer;
                objCmc.Encode();
                requestStr = objCmc.RawData;
            }
            else
            {
                _logger.Error("There is no thumbprint configured for \"enrollment_agent_cert_thumbprint\". The setting is required to enroll certificates. The current operation is aborted.");
            }

            //_logger.Log($"EOBO data:\n{requestStr}");
            return requestStr;
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
        /// <exception cref="Exception">General exception</exception>
        public CertSubmissionResult SendCertificateRequest(string caName, string certificateRequest, string templateName = "")
        {
            _logger.Log($"Sending\n{certificateRequest}\n to CA={caName}, templateName={templateName}");
            var objCertRequest = new CCertRequest();
            int disposition = 0;
            string attributes = "";

            if (!string.IsNullOrEmpty(templateName))
            {
                attributes = "CertificateTemplate:" + templateName;
            }

            // Convert the originial CSR to a EOBO CMC request which will contain the CN from the CSR as requester
            // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/cmc-eobo-request
            CertSubmissionResult? res = null;
            if (CreateEOBOCMCRequest(certificateRequest) is string actualCSR)
            {
                disposition = objCertRequest.Submit(CR_IN_BASE64 | CR_IN_FORMATANY, actualCSR, attributes, caName);
                string dispositionMessage = objCertRequest.GetDispositionMessage();

                _logger.Log($"Disposition: {disposition}");
                _logger.Log($"Disposition Message: {dispositionMessage}");

                uint lastStatus = (uint)objCertRequest.GetLastStatus();
                _logger.Log($"Disposition Message: {lastStatus}");

                res = new(disposition, dispositionMessage, objCertRequest.GetRequestId(), lastStatus);

            }
            else
            {
                throw new Exception("The CMC request could not be created or signed. Verify that the service is configured correctly.");
            }
            return res;
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
            _logger.Log($"Downloading Cert for requestID={requestId} from CA={caName}");
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
    }
}