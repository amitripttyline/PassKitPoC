package com.example.passkit.service;

import com.example.passkit.model.PassMetadata;
import com.example.passkit.repository.PassMetadataRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Service
public class PassGeneratorService {

    private static final Logger logger = LoggerFactory.getLogger(PassGeneratorService.class);

    @Value("${passkit.certificate.path:PassKITPoc/certs/pass-certificate.pem}")
    private String certificatePath;

    @Value("${passkit.privatekey.path:PassKITPoc/certs/pass-private-key.pem}")
    private String privateKeyPath;

    @Value("${passkit.wwdr.path:PassKITPoc/certs/wwdr.pem}")
    private String wwdrPath;

    @Value("${passkit.pass.typeIdentifier:pass.com.example.passkit}")
    private String passTypeIdentifier;

    @Value("${passkit.pass.teamIdentifier:YOUR_TEAM_ID}")
    private String teamIdentifier;

    @Value("${passkit.pass.organizationName:Example Organization}")
    private String organizationName;

    @Value("${passkit.webservice.url:}")
    private String webServiceURL;

    @Value("${passkit.auth.token:}")
    private String authenticationToken;

    @Autowired
    private PassMetadataRepository passMetadataRepository;

    @Autowired
    private APNsService apnsService;

    private PrivateKey privateKey;
    private X509Certificate passCertificate;
    private X509Certificate wwdrCertificate;

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
        // Certificates will be loaded when needed, or can be preloaded here
        // For now, we'll load them on demand to handle missing cert files gracefully
    }

    public byte[] generatePass() throws Exception {
        return generatePass(null);
    }

    public byte[] generatePass(String serialNumber) throws Exception {
        // Use provided serial number or generate new one
        if (serialNumber == null) {
            serialNumber = UUID.randomUUID().toString();
        }

        logger.info("Generating pass with serialNumber: {}, passTypeIdentifier: {}, teamIdentifier: {}", 
                serialNumber, passTypeIdentifier, teamIdentifier);

        // Create pass.json
        Map<String, Object> passJson = createPassJson(serialNumber);
        String passJsonString = new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValueAsString(passJson);
        
        logger.debug("Created pass.json with identifiers - passTypeIdentifier: {}, teamIdentifier: {}", 
                passTypeIdentifier, teamIdentifier);

        // Save or update pass metadata
        savePassMetadata(serialNumber, passJsonString);

        // Create manifest.json (include PNG files)
        Map<String, String> manifest = createManifest(passJsonString);
        String manifestJsonString = new ObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValueAsString(manifest);
        
        logger.debug("Created manifest.json with {} entries", manifest.size());

        // Sign manifest
        logger.info("Signing manifest with certificates...");
        byte[] signature = signManifest(manifestJsonString.getBytes(StandardCharsets.UTF_8));
        logger.info("Manifest signed successfully (signature size: {} bytes)", signature.length);

        // Create .pkpass zip file
        logger.info("Creating .pkpass zip file...");
        byte[] pkpass = createPkpassZip(passJsonString, manifestJsonString, signature);
        logger.info("Pass generated successfully (total size: {} bytes)", pkpass.length);
        
        return pkpass;
    }

    private void savePassMetadata(String serialNumber, String passJsonString) {
        Optional<PassMetadata> existingMetadata = passMetadataRepository.findBySerialNumber(serialNumber);
        PassMetadata metadata;

        if (existingMetadata.isPresent()) {
            // Existing pass - increment version
            metadata = existingMetadata.get();
            metadata.setPassData(passJsonString);
            metadata.incrementVersion();
        } else {
            // New pass
            metadata = new PassMetadata(serialNumber, passTypeIdentifier);
            metadata.setPassData(passJsonString);
        }

        passMetadataRepository.save(metadata);
    }

    public byte[] getUpdatedPass(String serialNumber) throws Exception {
        PassMetadata metadata = passMetadataRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new Exception("Pass not found: " + serialNumber));

        if (metadata.getStatus() != PassMetadata.PassStatus.ACTIVE) {
            throw new Exception("Pass is not active: " + metadata.getStatus());
        }

        return generatePass(serialNumber);
    }

    public void updatePass(String serialNumber) throws Exception {
        PassMetadata metadata = passMetadataRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new Exception("Pass not found: " + serialNumber));

        // Increment version
        metadata.incrementVersion();
        passMetadataRepository.save(metadata);

        // Notify registered devices
        apnsService.notifyPassUpdate(passTypeIdentifier, serialNumber);
    }

    private Map<String, Object> createPassJson(String serialNumber) {
        Map<String, Object> pass = new HashMap<>();

        pass.put("formatVersion", 1);
        pass.put("passTypeIdentifier", passTypeIdentifier);
        pass.put("serialNumber", serialNumber);
        pass.put("teamIdentifier", teamIdentifier);
        pass.put("organizationName", organizationName);
        pass.put("description", "Example Pass");

        // Add web service configuration if available
        if (webServiceURL != null && !webServiceURL.isEmpty()) {
            pass.put("webServiceURL", webServiceURL);
            pass.put("authenticationToken", authenticationToken);
        }

        // Barcode
        Map<String, Object> barcode = new HashMap<>();
        barcode.put("message", "123456789");
        barcode.put("format", "PKBarcodeFormatQR");
        barcode.put("messageEncoding", "iso-8859-1");
        pass.put("barcodes", Collections.singletonList(barcode));

        // Colors
        pass.put("backgroundColor", "rgb(60, 65, 76)");
        pass.put("foregroundColor", "rgb(255, 255, 255)");
        pass.put("labelColor", "rgb(255, 255, 255)");

        // Generic pass structure
        Map<String, Object> generic = new HashMap<>();

        // Primary fields
        Map<String, Object> primaryField = new HashMap<>();
        primaryField.put("key", "title");
        primaryField.put("label", "Pass Title");
        primaryField.put("value", "Sample Pass");
        generic.put("primaryFields", Collections.singletonList(primaryField));

        // Secondary fields
        Map<String, Object> secondaryField = new HashMap<>();
        secondaryField.put("key", "subtitle");
        secondaryField.put("label", "Subtitle");
        secondaryField.put("value", "PassKit POC");
        generic.put("secondaryFields", Collections.singletonList(secondaryField));

        // Auxiliary fields
        Map<String, Object> auxField = new HashMap<>();
        auxField.put("key", "info");
        auxField.put("label", "Information");
        auxField.put("value", "iOS + Spring Boot");
        generic.put("auxiliaryFields", Collections.singletonList(auxField));

        // Back fields
        Map<String, Object> backField = new HashMap<>();
        backField.put("key", "details");
        backField.put("label", "Details");
        backField.put("value", "This is a sample pass generated by Spring Boot backend for Apple Wallet.");
        generic.put("backFields", Collections.singletonList(backField));

        pass.put("generic", generic);

        return pass;
    }

    private Map<String, String> createManifest(String passJsonString) throws Exception {
        Map<String, String> manifest = new HashMap<>();

        // Hash pass.json
        String passHash = sha1Hash(passJsonString.getBytes(StandardCharsets.UTF_8));
        manifest.put("pass.json", passHash);

        // Hash PNG files if they exist
        try {
            byte[] iconPng = readResource("passkit/icon.png");
            manifest.put("icon.png", sha1Hash(iconPng));
            logger.debug("Added icon.png to manifest");
        } catch (Exception e) {
            logger.warn("Could not add icon.png to manifest: {}", e.getMessage());
        }

        try {
            byte[] icon2xPng = readResource("passkit/icon@2x.png");
            manifest.put("icon@2x.png", sha1Hash(icon2xPng));
            logger.debug("Added icon@2x.png to manifest");
        } catch (Exception e) {
            logger.warn("Could not add icon@2x.png to manifest: {}", e.getMessage());
        }

        try {
            byte[] icon3xPng = readResource("passkit/icon@3x.png");
            manifest.put("icon@3x.png", sha1Hash(icon3xPng));
            logger.debug("Added icon@3x.png to manifest");
        } catch (Exception e) {
            logger.warn("Could not add icon@3x.png to manifest: {}", e.getMessage());
        }

        return manifest;
    }

    private String sha1Hash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hash = digest.digest(data);
        return bytesToHex(hash);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    private byte[] signManifest(byte[] manifestData) throws Exception {
        // Load certificates if not already loaded
        if (privateKey == null || passCertificate == null || wwdrCertificate == null) {
            loadCertificates();
        }

        // Create CMS signed data
        CMSTypedData cmsData = new CMSProcessableByteArray(manifestData);

        // Certificate chain order: Pass Type ID certificate first, then WWDR certificate
        // This order is important for proper chain validation
        @SuppressWarnings("unchecked")
        Store<X509Certificate> certStore = new JcaCertStore(Arrays.asList(passCertificate, wwdrCertificate));

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);

        DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BC")
                .build();

        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(digestProvider)
                        .build(signer, passCertificate)
        );

        generator.addCertificates(certStore);

        CMSSignedData signedData = generator.generate(cmsData, false);

        return signedData.getEncoded();
    }

    private void loadCertificates() throws Exception {
        try {
            // Load private key - try multiple path locations
            String resolvedPrivateKeyPath = resolveCertificatePath(privateKeyPath, "private key");
            logger.info("Loading private key from: {}", resolvedPrivateKeyPath);
            
            try (PEMParser pemParser = new PEMParser(new FileReader(resolvedPrivateKeyPath))) {
                Object object = pemParser.readObject();
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                if (object instanceof PrivateKeyInfo) {
                    privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
                    logger.info("Successfully loaded private key");
                } else {
                    throw new Exception("Private key file does not contain a valid private key");
                }
            }

            // Load pass certificate - try multiple path locations
            String resolvedCertPath = resolveCertificatePath(certificatePath, "pass certificate");
            logger.info("Loading pass certificate from: {}", resolvedCertPath);
            
            try (FileInputStream fis = new FileInputStream(resolvedCertPath)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                passCertificate = (X509Certificate) cf.generateCertificate(fis);
                String certSubject = passCertificate.getSubjectX500Principal().toString();
                logger.info("Successfully loaded pass certificate. Subject: {}", certSubject);
            }

            // Load WWDR certificate - try multiple path locations
            String resolvedWwdrPath = resolveCertificatePath(wwdrPath, "WWDR certificate");
            logger.info("Loading WWDR certificate from: {}", resolvedWwdrPath);
            
            try (FileInputStream fis = new FileInputStream(resolvedWwdrPath)) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                wwdrCertificate = (X509Certificate) cf.generateCertificate(fis);
                String wwdrSubject = wwdrCertificate.getSubjectX500Principal().toString();
                logger.info("Successfully loaded WWDR certificate. Subject: {}", wwdrSubject);
            }
            
            // Verify certificates are valid
            verifyCertificates();
            
            // Verify private key matches certificate
            verifyPrivateKeyMatchesCertificate();
            
        } catch (Exception e) {
            logger.error("Failed to load certificates: {}", e.getMessage(), e);
            throw new Exception("Failed to load certificates. Please ensure all certificate files are present and valid. " +
                    "Error: " + e.getMessage() + 
                    ". Checked paths: privateKey=" + privateKeyPath + 
                    ", certificate=" + certificatePath + 
                    ", wwdr=" + wwdrPath, e);
        }
    }
    
    private void verifyPrivateKeyMatchesCertificate() throws Exception {
        if (privateKey == null || passCertificate == null) {
            return;
        }
        
        try {
            // Try to create a signature with the private key and verify with the certificate's public key
            java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            byte[] testData = "test".getBytes();
            signature.update(testData);
            byte[] sigBytes = signature.sign();
            
            signature.initVerify(passCertificate.getPublicKey());
            signature.update(testData);
            boolean verified = signature.verify(sigBytes);
            
            if (verified) {
                logger.info("Private key matches the pass certificate");
            } else {
                throw new Exception("Private key does not match the pass certificate");
            }
        } catch (Exception e) {
            logger.error("Failed to verify private key matches certificate: {}", e.getMessage());
            throw new Exception("Private key verification failed. The private key may not match the certificate: " + e.getMessage(), e);
        }
    }
    
    private String resolveCertificatePath(String configuredPath, String certificateType) throws FileNotFoundException {
        // Try the configured path as-is (could be absolute or relative)
        java.nio.file.Path path = Paths.get(configuredPath);
        if (Files.exists(path) && Files.isRegularFile(path)) {
            return path.toAbsolutePath().toString();
        }
        
        // Try relative to project root (when running from project root)
        String[] alternativePaths = {
            configuredPath,  // Original path
            "../" + configuredPath,  // If running from backend directory
            "../../" + configuredPath,  // If running from backend/target directory
            "certs/" + new java.io.File(configuredPath).getName(),  // Try root certs folder
            "../certs/" + new java.io.File(configuredPath).getName()  // Try root certs from backend
        };
        
        for (String altPath : alternativePaths) {
            path = Paths.get(altPath);
            if (Files.exists(path) && Files.isRegularFile(path)) {
                logger.debug("Found {} at alternative path: {}", certificateType, path.toAbsolutePath());
                return path.toAbsolutePath().toString();
            }
        }
        
        // If still not found, provide helpful error message
        StringBuilder errorMsg = new StringBuilder();
        errorMsg.append(certificateType).append(" not found at: ").append(configuredPath);
        errorMsg.append("\nTried paths:");
        for (String altPath : alternativePaths) {
            errorMsg.append("\n  - ").append(Paths.get(altPath).toAbsolutePath());
        }
        errorMsg.append("\nCurrent working directory: ").append(System.getProperty("user.dir"));
        
        throw new FileNotFoundException(errorMsg.toString());
    }
    
    private void verifyCertificates() throws Exception {
        // Verify passTypeIdentifier matches certificate
        if (passCertificate != null) {
            String certSubject = passCertificate.getSubjectX500Principal().toString();
            logger.info("Verifying certificate matches passTypeIdentifier: {}", passTypeIdentifier);
            logger.info("Certificate subject: {}", certSubject);
            
            // Check if this is a test certificate
            boolean isTestCertificate = certSubject.contains("Test Certificate") || 
                                       certSubject.contains("Test Organization") ||
                                       certSubject.contains("test");
            
            if (isTestCertificate) {
                logger.error("WARNING: This appears to be a TEST certificate, not a real Apple Pass Type ID certificate!");
                logger.error("Test certificates will NOT work with Apple Wallet.");
                logger.error("You need a real Pass Type ID certificate from Apple Developer Portal.");
                logger.error("Certificate subject: {}", certSubject);
                logger.error("Expected CN should contain: {}", passTypeIdentifier);
                logger.error("Expected OU should be: {}", teamIdentifier);
                throw new Exception("Test certificate detected. Apple Wallet requires a real Pass Type ID certificate from Apple Developer Portal. " +
                        "The certificate subject '" + certSubject + "' does not match the required format. " +
                        "Please obtain a real Pass Type ID certificate from https://developer.apple.com/account/resources/identifiers/list/passTypeId");
            }
            
            // Extract certificate details
            String cn = null;
            String ou = null;
            String[] subjectParts = certSubject.split(",");
            for (String part : subjectParts) {
                part = part.trim();
                if (part.startsWith("CN=")) {
                    cn = part.substring(3);
                    logger.info("Certificate Common Name (CN): {}", cn);
                    // The CN should match or contain the passTypeIdentifier
                    if (!cn.equals(passTypeIdentifier) && !cn.contains(passTypeIdentifier) && !passTypeIdentifier.contains(cn)) {
                        logger.warn("Certificate CN '{}' does not match passTypeIdentifier '{}'", cn, passTypeIdentifier);
                        logger.warn("This may cause Apple Wallet to reject the pass");
                    } else {
                        logger.info("✓ Certificate CN matches passTypeIdentifier");
                    }
                } else if (part.startsWith("OU=")) {
                    ou = part.substring(3);
                    logger.info("Certificate Organizational Unit (OU): {}", ou);
                    // The OU should match the teamIdentifier
                    if (ou.equals(teamIdentifier)) {
                        logger.info("✓ Team identifier matches certificate OU");
                    } else {
                        logger.warn("Team identifier '{}' does not match certificate OU '{}'", teamIdentifier, ou);
                        logger.warn("This may cause Apple Wallet to reject the pass");
                    }
                }
            }
            
            if (cn == null) {
                logger.warn("Certificate does not have a CN (Common Name) field");
            }
            if (ou == null) {
                logger.warn("Certificate does not have an OU (Organizational Unit) field - this is required for teamIdentifier");
            }
            
            // Verify certificate is not expired
            try {
                passCertificate.checkValidity();
                logger.info("✓ Pass certificate is valid (not expired)");
            } catch (Exception e) {
                logger.error("Pass certificate validation failed: {}", e.getMessage());
                throw new Exception("Pass certificate is expired or invalid: " + e.getMessage(), e);
            }
        }
        
        // Verify WWDR certificate
        if (wwdrCertificate != null) {
            String wwdrSubject = wwdrCertificate.getSubjectX500Principal().toString();
            logger.info("WWDR certificate subject: {}", wwdrSubject);
            
            // Verify WWDR certificate is from Apple
            if (!wwdrSubject.contains("Apple") && !wwdrSubject.contains("Worldwide Developer Relations")) {
                logger.warn("  WWDR certificate may not be the official Apple WWDR certificate");
            } else {
                logger.info("  WWDR certificate appears to be from Apple");
            }
            
            try {
                wwdrCertificate.checkValidity();
                logger.info("✓ WWDR certificate is valid (not expired)");
            } catch (Exception e) {
                logger.error("WWDR certificate validation failed: {}", e.getMessage());
                throw new Exception("WWDR certificate is expired or invalid: " + e.getMessage(), e);
            }
        }
    }

    private byte[] createPkpassZip(String passJsonString, String manifestJsonString, byte[] signature) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            // Add pass.json
            ZipEntry passEntry = new ZipEntry("pass.json");
            zos.putNextEntry(passEntry);
            zos.write(passJsonString.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // Add manifest.json
            ZipEntry manifestEntry = new ZipEntry("manifest.json");
            zos.putNextEntry(manifestEntry);
            zos.write(manifestJsonString.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            // Add signature
            ZipEntry signatureEntry = new ZipEntry("signature");
            zos.putNextEntry(signatureEntry);
            zos.write(signature);
            zos.closeEntry();

            //add png files
            try {
                byte[] iconPng = readResource("passkit/icon.png");
                ZipEntry pngLogo = new ZipEntry("icon.png");
                zos.putNextEntry(pngLogo);
                zos.write(iconPng);
                zos.closeEntry();
                logger.info("Successfully added icon.png to pass ({} bytes)", iconPng.length);
            } catch (Exception e) {
                logger.error("Could not load icon.png: {}", e.getMessage(), e);
            }

            try {
                byte[] icon2xPng = readResource("passkit/icon@2x.png");
                ZipEntry pngLogo2 = new ZipEntry("icon@2x.png");
                zos.putNextEntry(pngLogo2);
                zos.write(icon2xPng);
                zos.closeEntry();
                logger.info("Successfully added icon@2x.png to pass ({} bytes)", icon2xPng.length);
            } catch (Exception e) {
                logger.error("Could not load icon@2x.png: {}", e.getMessage(), e);
            }

            try {
                byte[] icon3xPng = readResource("passkit/icon@3x.png");
                ZipEntry pngLogo3 = new ZipEntry("icon@3x.png");
                zos.putNextEntry(pngLogo3);
                zos.write(icon3xPng);
                zos.closeEntry();
                logger.info("Successfully added icon@3x.png to pass ({} bytes)", icon3xPng.length);
            } catch (Exception e) {
                logger.error("Could not load icon@3x.png: {}", e.getMessage(), e);
            }
        }

        return baos.toByteArray();
    }

    private byte[] readResource(String path) throws IOException {
        ClassPathResource res = new ClassPathResource(path);
        if (!res.exists()) {
            throw new FileNotFoundException("Resource not found: " + path + " (checked classpath)");
        }
        try (InputStream in = res.getInputStream()) {
            byte[] data = in.readAllBytes();
            logger.debug("Loaded resource {}: {} bytes", path, data.length);
            return data;
        }
    }
}

