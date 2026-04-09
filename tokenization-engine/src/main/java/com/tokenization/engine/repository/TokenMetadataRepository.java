package com.tokenization.engine.repository;

import com.tokenization.engine.entity.TokenMetadata;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * JPA repository for token metadata.
 *
 * <p>WHY: Spring Data JPA is used for standard CRUD. Custom queries are minimal
 * because token_metadata lookups are always by primary key (tokenId) for performance.</p>
 */
@Repository
public interface TokenMetadataRepository extends JpaRepository<TokenMetadata, String> {

    /** Find all tokens for a tenant (for admin/audit purposes). */
    List<TokenMetadata> findByTenantId(String tenantId);

    /** Find tokens by data type and tenant (for key rotation migration). */
    List<TokenMetadata> findByTenantIdAndDataType(String tenantId,
        com.tokenization.common.model.DataType dataType);
}
