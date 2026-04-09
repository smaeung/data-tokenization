package com.tokenization.engine.entity;

import com.tokenization.common.model.DataType;
import jakarta.persistence.*;
import java.time.Instant;

/**
 * JPA entity for token metadata storage.
 *
 * <p>WHY: In a vaultless architecture, we do NOT store the mapping between token and plaintext.
 * This table stores only the metadata needed to reconstruct the correct detokenization parameters:
 * - dataType: to select the correct FF1 radix and alphabet
 * - keyVersion: to retrieve the correct historical key from the key provider
 * - tenantId: for multi-tenant isolation enforcement
 *
 * WITHOUT the cryptographic key (stored in Vault/HSM), this metadata is useless for reconstruction.</p>
 *
 * <p>SECURITY: The absence of plaintext or token-to-plaintext mapping is the core security property
 * of vaultless tokenization — even full database compromise does not reveal sensitive data.</p>
 */
@Entity
@Table(name = "token_metadata")
public class TokenMetadata {

    @Id
    @Column(name = "token_id", length = 256)
    private String tokenId;

    @Enumerated(EnumType.STRING)
    @Column(name = "data_type", nullable = false, length = 64)
    private DataType dataType;

    @Column(name = "format", nullable = false, length = 64)
    private String format;

    /**
     * The key version used during tokenization.
     * WHY: Critical for detokenization after key rotation — we must use the SAME
     * key version that was used to create the token, not the current active version.
     */
    @Column(name = "key_version", nullable = false)
    private int keyVersion;

    @Column(name = "tenant_id", nullable = false, length = 128)
    private String tenantId;

    @Column(name = "created_at")
    private Instant createdAt;

    public String getTokenId() { return tokenId; }
    public void setTokenId(String tokenId) { this.tokenId = tokenId; }
    public DataType getDataType() { return dataType; }
    public void setDataType(DataType dataType) { this.dataType = dataType; }
    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }
    public int getKeyVersion() { return keyVersion; }
    public void setKeyVersion(int keyVersion) { this.keyVersion = keyVersion; }
    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
