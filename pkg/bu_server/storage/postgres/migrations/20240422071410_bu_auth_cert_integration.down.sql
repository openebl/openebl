DROP TABLE cert_revocation_list;
DROP TABLE root_cert;
ALTER TABLE business_unit_authentication DROP COLUMN cert_fingerprint;
ALTER TABLE business_unit_authentication DROP COLUMN cert_public_key_id;
ALTER TABLE business_unit_authentication DROP COLUMN cert_issuer_key_id;
ALTER TABLE business_unit_authentication DROP COLUMN cert_serial;
