using Grpc;
using Grpc.Core;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static Grpc.CAService;

namespace CAService
{
    internal class GrpcServer : CAServiceBase
    {
        private Server? _server;
        private readonly ILogger<PrivacyIDEACAService> _logger;
        private LdapOperations _ldapOp;
        private CertEnrollLibWrapper _certEnroll;

        public Dictionary<string, string> options = new();

        public GrpcServer(ILogger<PrivacyIDEACAService> logger, Settings settings)
        {
            _logger = logger;
            _certEnroll = new CertEnrollLibWrapper(logger);

            _ldapOp = new LdapOperations(Settings.LDAP_DOMAIN ?? "", Settings.LDAP_SERVER ?? "");
            _ldapOp._logger = _logger;

            SetupServer();
        }

        private X509Certificate2Collection GetCertificatesFromStore(StoreName storeName, string subjectName)
        {
            X509Store store = new(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection collection = store.Certificates;
            var fcollection = collection.Find(X509FindType.FindBySubjectName, subjectName, true);
            store.Close();
            return fcollection;
        }

        private string GetPublicKeyPEM(X509Certificate2 certificate)
        {
            var publicKey = certificate.PublicKey;
            var publicKeyBytes = publicKey.ExportSubjectPublicKeyInfo();
            string pemPublicKey = new(PemEncoding.Write("PUBLIC KEY", publicKeyBytes));
            return pemPublicKey;
        }

        private void SetupServer()
        {
            ServerCredentials credentials = ServerCredentials.Insecure;

            if (!Settings.SERVER_USE_UNSAFE_CREDENTIALS)
            {
                // Get the CA cert from the store
                string caSubjectName = Settings.SERVER_CA_CERT_SUBJECT_NAME;
                if (string.IsNullOrEmpty(caSubjectName))
                {
                    _logger.LogInformation($"No subjectName for CA certificate configured, aborting server start!");
                    return;
                }

                var caCertCandidates = GetCertificatesFromStore(StoreName.Root, caSubjectName);
                X509Certificate2? caCert = null;
                if (caCertCandidates.Count < 1)
                {
                    _logger.LogInformation($"No CA certificate found in LocalMachine store for subjectName {caSubjectName}, aborting server start!");
                    return;
                }
                else if (caCertCandidates.Count > 1)
                {
                    _logger.LogInformation($"Mutliple CA certificates found in LocalMachine store for subjectName {caSubjectName}, using first.");
                    caCert = caCertCandidates[0];
                }
                else
                {
                    caCert = caCertCandidates[0];
                }

                string caCertPEM = GetPublicKeyPEM(caCert);

                // Get the server cert from the store
                string subjectName = Settings.SERVER_CERT_SUBJECT_NAME;
                if (string.IsNullOrEmpty(subjectName))
                {
                    _logger.LogInformation($"No subjectName configured, aborting server start!");
                    return;
                }
                var fcollection = GetCertificatesFromStore(StoreName.My, subjectName);
                X509Certificate2? serverCert;
                if (fcollection.Count < 1)
                {
                    _logger.LogInformation($"No certificate found in LocalMachine store for subjectName {subjectName}, aborting server start!");
                    return;
                }
                else if (fcollection.Count > 1)
                {
                    _logger.LogInformation($"Mutliple certificates found in LocalMachine store for subjectName {subjectName}, using first.");
                    serverCert = fcollection[0];
                }
                else
                {
                    serverCert = fcollection[0];
                }
                // The server certificate need to contain the private key
                if (!serverCert.HasPrivateKey)
                {
                    _logger.LogInformation("Server certificate does not contain the private key and can not be used, aborting server start!");
                    return;
                }
                // TODO update deprecrated
                var privateKey = serverCert.PrivateKey;
                string pemPrivateKey = "";
                if (privateKey is not null)
                {
                    var privateKeyBytes = privateKey.ExportPkcs8PrivateKey();
                    pemPrivateKey = new(PemEncoding.Write("PRIVATE KEY", privateKeyBytes));
                }

                string pemPublicKey = GetPublicKeyPEM(serverCert);

                KeyCertificatePair keypair = new(pemPublicKey, pemPrivateKey);
                // TODO make this more configurable?
                SslClientCertificateRequestType clientReqType = Settings.SERVER_FORCE_CLIENT_AUTH ? SslClientCertificateRequestType.RequestAndRequireAndVerify : SslClientCertificateRequestType.RequestAndVerify;
                credentials = new SslServerCredentials(new List<KeyCertificatePair>() { keypair }, caCertPEM, clientReqType);
                _logger.LogInformation("Starting server with secure credentials, forceClientAuth=" + clientReqType.ToString("G"));
            }
            else
            {
                _logger.LogInformation("Starting server with insecure credentials...");
            }

            _server = new Server
            {
                // TODO server credentials
                Ports = { new ServerPort(Settings.BIND_ADDRESS, Settings.BIND_PORT, credentials) },
                Services = { BindService(this) }
            };
            var host = _server.Ports.ElementAt(0).Host;
            var port = _server.Ports.ElementAt(0).Port;
            _logger.LogInformation($"Starting server at {host} and port {port} in thread {Thread.CurrentThread.ManagedThreadId}");
        }

        public void Start()
        {
            _server?.Start();
        }

        public Task? Stop()
        {
            return _server?.KillAsync();
        }

        public override Task<GetTemplatesReply> GetTemplates(GetTemplatesRequest request, ServerCallContext context)
        {
            _logger.LogInformation("GetTemplates");

            var reply = new GetTemplatesReply
            {
                Status = new()
            };

            IEnumerable<CertificateTemplate> templateList;
            try
            {
                templateList = _ldapOp.GetCertificateTemplates();
            }
            catch (Exception ex)
            {
                _logger.LogError($"GetCertificateTemplates encountered an error:\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            if (templateList is not null)
            {
                reply.TemplateNames.AddRange(templateList.Select(template => template.Name));
            }

            _logger.LogInformation($"Replying with template name list: {string.Join(", ", reply.TemplateNames)}");
            return Task.FromResult(reply);
        }

        public override Task<GetCAsReply> GetCAs(GetCAsRequest request, ServerCallContext context)
        {
            _logger.LogInformation("GetCAs");
            var reply = new GetCAsReply
            {
                Status = new()
            };

            IEnumerable<EnterpriseCertificateAuthority> caList;
            try
            {
                caList = _ldapOp.GetEnterpriseCAs();
            }
            catch (Exception ex)
            {
                _logger.LogError($"GetEnterpriseCAs encountered an error:\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            if (caList is not null)
            {
                reply.CaNames.AddRange(caList.Select(ca => ca.FullName));
            }

            _logger.LogInformation($"Replying with CA list: {string.Join(", ", reply.CaNames)}");
            return Task.FromResult(reply);
        }

        public override Task<GetCertificateReply> GetCertificate(GetCertificateRequest request, ServerCallContext context)
        {
            _logger.LogInformation($"GetCertificate for id {request.Id} from CA {request.CaName}");
            int id = request.Id;
            var reply = new GetCertificateReply
            {
                Status = new(),
                Cert = ""
            };

            if (request.Id == 0 || string.IsNullOrEmpty(request.CaName))
            {
                _logger.LogInformation("Invalid Parameter. RequestId = 0 or CA Name empty!");
                reply.Status.Code = 1;
                reply.Status.Message = "Invalid Parameter. RequestId = 0 or CA Name empty!";
                return Task.FromResult(reply);
            }

            string? cert;
            try
            {
                cert = _certEnroll.DownloadCert(request.CaName, id);
            }
            catch (COMException comex)
            {
                _logger.LogError($"DownloadCert encountered a COMException:\n{comex.StackTrace}");
                reply.Status.Code = comex.ErrorCode;
                reply.Status.Message = comex.Message;
                return Task.FromResult(reply);
            }
            catch (Exception ex)
            {
                _logger.LogError($"DownloadCert encountered an error:\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            if (cert != null)
            {
                reply.Cert = cert;
            }
            else
            {
                _logger.LogInformation("Retrieved an empty response from the CA.");
            }

            return Task.FromResult(reply);
        }

        public override Task<GetCSRStatusReply> GetCSRStatus(GetCSRStatusRequest request, ServerCallContext context)
        {
            _logger.LogInformation($"GetCRStatus for ID {request.CertRequestId} from CA {request.CaName}");
            var reply = new GetCSRStatusReply
            {
                Status = new()
            };
            if (string.IsNullOrEmpty(request.CaName) || request.CertRequestId == 0)
            {
                reply.Status.Code = 1;
                reply.Status.Message = "CA Name empty or CertRequestId is 0";
                return Task.FromResult(reply);
            }
            try
            {
                reply.Disposition = _certEnroll.GetRequestStatus(request.CertRequestId, null, request.CaName);
            }
            catch (COMException comex)
            {
                _logger.LogError($"GetRequestStatus encountered a COMException:\n{comex.StackTrace}");
                reply.Status.Code = comex.ErrorCode;
                reply.Status.Message = comex.Message;
                return Task.FromResult(reply);
            }
            catch (Exception ex)
            {
                _logger.LogError($"GetRequestStatus encountered an error:\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            reply.DispositionMessage = _certEnroll.GetDispositionMessage() ?? "";
            _logger.LogInformation($"Returning dispositon {reply.Disposition}");
            return Task.FromResult(reply);
        }

        public override Task<SubmitCSRReply> SubmitCSR(SubmitCSRRequest request, ServerCallContext context)
        {
            _logger.LogInformation($"Submitting CR to {request.CaName} for template {request.TemplateName}. CR:\n{request.Csr}");
            var reply = new SubmitCSRReply
            {
                Status = new()
            };

            if (string.IsNullOrEmpty(request.TemplateName))
            {
                _logger.LogInformation("TemplateName is empty!");
                reply.Status.Code = 1;
                reply.Status.Message = "TemplateName is empty!";
                return Task.FromResult(reply);
            }

            if (string.IsNullOrEmpty(request.Csr))
            {
                _logger.LogInformation("CertificateRequest is empty!");
                reply.Status.Code = 1;
                reply.Status.Message = "CertificateRequest is empty!";
                return Task.FromResult(reply);
            }

            if (string.IsNullOrEmpty(request.CaName))
            {
                _logger.LogInformation("CA Name is empty!");
                reply.Status.Code = 1;
                reply.Status.Message = "CA Name is empty!";
                return Task.FromResult(reply);
            }

            CertSubmissionResult ret;
            try
            {
                ret = _certEnroll.SendCertificateRequest(request.CaName, request.Csr, templateName: request.TemplateName);
            }
            catch (COMException comex)
            {
                _logger.LogError($"SendCertificateRequest encountered a COMException:\n{comex.StackTrace}");
                reply.Status.Code = comex.ErrorCode;
                reply.Status.Message = comex.Message;
                return Task.FromResult(reply);
            }
            catch (Exception ex)
            {
                _logger.LogError($"SendCertificateRequest encountered an error:\n{ex.StackTrace}");
                reply.Status.Code = 1;
                reply.Status.Message = ex.Message;
                return Task.FromResult(reply);
            }

            reply.RequestId = ret.RequestId;
            reply.Disposition = ret.Disposition;
            reply.DispositionMessage = ret.DispositionMessage;
            reply.Status.Code = 0;
            reply.Status.Message = "";
            return Task.FromResult(reply);
        }

        public override Task<SetOptionReply> SetOption(SetOptionRequest request, ServerCallContext context)
        {
            SetOptionReply reply = new()
            {
                Status = new()
            };
            if (!string.IsNullOrEmpty(request.OptionName))
            {
                if (options.TryGetValue(request.OptionName, out string? value))
                {
                    _logger.LogInformation($"Overwriting Option {request.OptionName}={value} with new value {request.OptionValue}");
                }

                options.Add(request.OptionName, request.OptionValue);
                reply.Status.Code = 0;
                reply.Status.Message = "";
            }
            else
            {
                reply.Status.Code = 1;
                reply.Status.Message = "OptionName cannot be empty";
            }

            return Task.FromResult(reply);
        }

        public override Task<GetOptionsReply> GetOptions(GetOptionsRequest request, ServerCallContext context)
        {
            GetOptionsReply reply = new()
            {
                Status = new()
                {
                    Code = 0,
                    Message = ""
                }
            };

            foreach (var pair in options)
            {
                if (!string.IsNullOrEmpty(pair.Key))
                {
                    reply.Options.Add(pair.Key, pair.Value);
                }
                else
                {
                    _logger.LogInformation($"Empty option name with value {pair.Value} will be skipped");
                }
            }

            return Task.FromResult(reply);
        }
    }
}
