#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

/*********** where is the ca certificate .pem file ****************************/
#define CACERT          "./rootCA.pem"
/*********** where is the ca's private key file *******************************/
#define CAKEY           "./rootCA.key"
/*********** The password for the ca's private key ****************************/
#define PASS            "password"


RSA* generate_rsa()
{
    const int kBits = 2048;

    int keylen;
    char *pem_key;

    BIGNUM *bne = NULL;
    unsigned long   e = RSA_F4;

    bne = BN_new();
    BN_set_word(bne, e);

    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, kBits, bne, NULL);

    /* To get the C-string PEM form: */
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    keylen = BIO_pending(bio);
    pem_key = calloc(keylen+1, 1); /* Null-terminate */
    BIO_read(bio, pem_key, keylen);

    printf("%s", pem_key);

    BIO_free_all(bio);
    free(pem_key);
    BN_free(bne);
    return rsa;
}


int generate_csr(RSA *rsa)
{
   const char      *szPath = "x509Req.pem";
   X509_REQ        *x509_req = NULL;
   X509_NAME       *x509_name = NULL;

   const char      *szCountry = "CA";
   const char      *szProvince = "BC";
   const char      *szCity = "Vancouver";
   const char      *szOrganization = "Dynamsoft";
   const char      *szCommon = "localhost";
   EVP_PKEY        *pKey = NULL;
   BIO             *out = NULL; //, *bio_err = NULL;

   int nVersion = 1;
   int ret;
   x509_req = X509_REQ_new();
   ret = X509_REQ_set_version(x509_req, nVersion);
   if (ret != 1){
       goto free_all;
   }

   x509_name = X509_REQ_get_subject_name(x509_req);

   ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
   if (ret != 1){
       goto free_all;
   }

   ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
   if (ret != 1){
       goto free_all;
   }

   ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
   if (ret != 1){
       goto free_all;
   }

   ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
   if (ret != 1){
       goto free_all;
   }

   ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
   if (ret != 1){
       goto free_all;
   }

    pKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pKey, rsa);
    rsa = NULL;   // will be free rsa when EVP_PKEY_free(pKey)

    ret = X509_REQ_set_pubkey(x509_req, pKey);
    if (ret != 1){
        goto free_all;
    }

    // 5. set sign key of x509 req
    ret = X509_REQ_sign(x509_req, pKey, EVP_sha1());    // return x509_req->signature->length
    if (ret <= 0){
        goto free_all;
    }

    out = BIO_new_file(szPath,"w");
    ret = PEM_write_bio_X509_REQ(out, x509_req);

   free_all:
   X509_REQ_free(x509_req);
   BIO_free_all(out);
   EVP_PKEY_free(pKey);
   return (ret == 1);
}


int sign(char* request_str) {

  BIO               *reqbio = NULL;
  BIO               *outbio = NULL;
  X509_REQ         *certreq = NULL;


  ASN1_INTEGER                 *aserial = NULL;
  EVP_PKEY                     *ca_privkey, *req_pubkey;
  EVP_MD                       const *digest = NULL;
  X509                         *newcert, *cacert;
  X509_NAME                    *name;
  X509V3_CTX                   ctx;
  FILE                         *fp;
  long                         valid_secs = 31536000;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  outbio  = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the request data in a BIO, then in a x509_REQ struct. *
   * ---------------------------------------------------------- */
  reqbio = BIO_new_mem_buf(request_str, -1);

  if (! (certreq = PEM_read_bio_X509_REQ(reqbio, NULL, NULL, NULL))) {
    BIO_printf(outbio, "Error can't read X509 request data into memory\n");
    goto free;
   }

  /* -------------------------------------------------------- *
   * Load ithe signing CA Certificate file                    *
   * ---------------------------------------------------------*/
  if (! (fp=fopen(CACERT, "r"))) {
    BIO_printf(outbio, "Error reading CA cert file\n");
    goto free;
   }

  if(! (cacert = PEM_read_X509(fp,NULL,NULL,NULL))) {
    BIO_printf(outbio, "Error loading CA cert into memory\n");
    goto free;
   }

  fclose(fp);

  /* -------------------------------------------------------- *
   * Import CA private key file for signing                   *
   * ---------------------------------------------------------*/
  ca_privkey = EVP_PKEY_new();

  if (! (fp = fopen (CAKEY, "r"))) {
    BIO_printf(outbio, "Error reading CA private key file\n");
    goto free;
   }

  if (! (ca_privkey = PEM_read_PrivateKey( fp, NULL, NULL, PASS))) {
    BIO_printf(outbio, "Error importing key content from file\n");
    goto free;
   }

  fclose(fp);

  /* --------------------------------------------------------- *
   * Build Certificate with data from request                  *
   * ----------------------------------------------------------*/
  if (! (newcert=X509_new())) {
    BIO_printf(outbio, "Error creating new X509 object\n");
    goto free;
   }

  if (X509_set_version(newcert, 2) != 1) {
    BIO_printf(outbio, "Error setting certificate version\n");
    goto free;
   }

  /* --------------------------------------------------------- *
   * set the certificate serial number here                    *
   * If there is a problem, the value defaults to '0'          *
   * ----------------------------------------------------------*/
  aserial=ASN1_INTEGER_new();
  ASN1_INTEGER_set(aserial, 0);
  if (! X509_set_serialNumber(newcert, aserial)) {
    BIO_printf(outbio, "Error setting serial number of the certificate\n");
    goto free;
   }

  /* --------------------------------------------------------- *
   * Extract the subject name from the request                 *
   * ----------------------------------------------------------*/
  if (! (name = X509_REQ_get_subject_name(certreq)))
    BIO_printf(outbio, "Error getting subject from cert request\n");

  /* --------------------------------------------------------- *
   * Set the new certificate subject name                      *
   * ----------------------------------------------------------*/
  if (X509_set_subject_name(newcert, name) != 1) {
    BIO_printf(outbio, "Error setting subject name of certificate\n");
    goto free;
   }

  /* --------------------------------------------------------- *
   * Extract the subject name from the signing CA cert         *
   * ----------------------------------------------------------*/
  if (! (name = X509_get_subject_name(cacert))) {
    BIO_printf(outbio, "Error getting subject from CA certificate\n");
    goto free;
   }

  /* --------------------------------------------------------- *
   * Set the new certificate issuer name                       *
   * ----------------------------------------------------------*/
  if (X509_set_issuer_name(newcert, name) != 1) {
    BIO_printf(outbio, "Error setting issuer name of certificate\n");
    goto free;
   }

  /* --------------------------------------------------------- *
   * Extract the public key data from the request              *
   * ----------------------------------------------------------*/
  if (! (req_pubkey=X509_REQ_get_pubkey(certreq))) {
    BIO_printf(outbio, "Error unpacking public key from request\n");
    goto free;
   }

  /* --------------------------------------------------------- *
   * Optionally: Use the public key to verify the signature    *
   * ----------------------------------------------------------*/
  if (X509_REQ_verify(certreq, req_pubkey) != 1) {
    BIO_printf(outbio, "Error verifying signature on request\n");
    goto free;
   }

  /* --------------------------------------------------------- *
   * Set the new certificate public key                        *
   * ----------------------------------------------------------*/
  if (X509_set_pubkey(newcert, req_pubkey) != 1) {
    BIO_printf(outbio, "Error setting public key of certificate\n");
    goto free;
   }

  /* ---------------------------------------------------------- *
   * Set X509V3 start date (now) and expiration date (+365 days)*
   * -----------------------------------------------------------*/
   if (! (X509_gmtime_adj(X509_get_notBefore(newcert),0))) {
      BIO_printf(outbio, "Error setting start time\n");
    goto free;
   }

   if(! (X509_gmtime_adj(X509_get_notAfter(newcert), valid_secs))) {
      BIO_printf(outbio, "Error setting expiration time\n");
    goto free;
   }

  /* ----------------------------------------------------------- *
   * Add X509V3 extensions                                       *
   * ------------------------------------------------------------*/
  X509V3_set_ctx(&ctx, cacert, newcert, NULL, NULL, 0);
  //X509_EXTENSION *ext;

  /* ----------------------------------------------------------- *
   * Set digest type, sign new certificate with CA's private key *
   * ------------------------------------------------------------*/
  digest = EVP_sha256();

  if (! X509_sign(newcert, ca_privkey, digest)) {
    BIO_printf(outbio, "Error signing the new certificate\n");
    goto free;
   }

  /* ------------------------------------------------------------ *
   *  print the certificate                                       *
   * -------------------------------------------------------------*/
  if (! PEM_write_bio_X509(outbio, newcert)) {
    BIO_printf(outbio, "Error printing the signed certificate\n");
    goto free;
   }

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */

  free:
  EVP_PKEY_free(req_pubkey);
  EVP_PKEY_free(ca_privkey);
  X509_REQ_free(certreq);
  X509_free(newcert);
  BIO_free_all(reqbio);
  BIO_free_all(outbio);
  return 0;
}
