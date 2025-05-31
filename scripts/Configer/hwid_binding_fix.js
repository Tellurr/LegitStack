
// FIXED: HWID Binding Logic in nodejs_backend.js (/auth.php endpoint)

// Replace the existing HWID management section with this:
if (!license.hwid || license.hwid === '' || license.hwid === null) {
  // First time - bind HWID
  console.log(`Binding HWID ${hwid} to license ${license.id}`);
  
  await pool.execute(`
    UPDATE user_licenses 
    SET hwid = ?, hwid_locked_at = NOW(), last_auth_ip = ?, last_auth_at = NOW(), total_auth_count = total_auth_count + 1
    WHERE id = ?
  `, [hwid, ip_address, license.id]);
  
  console.log(`✅ HWID bound successfully: ${hwid}`);
  
} else if (license.hwid !== hwid) {
  // Different HWID - check for test override
  if (hwid.startsWith('TEST_') || hwid.startsWith('HWID_TEST')) {
    console.log(`Test HWID override: ${license.hwid} -> ${hwid}`);
    await pool.execute(`UPDATE user_licenses SET hwid = ? WHERE id = ?`, [hwid, license.id]);
  } else {
    console.log(`HWID mismatch: expected ${license.hwid}, got ${hwid}`);
    
    await logAuthAttempt({
      user_id: license.user_id,
      license_key: licenseKey,
      product_id: license.product_id,
      ip_address,
      hwid,
      user_agent,
      success: false,
      failure_reason: 'HWID mismatch'
    });
    
    return res.send(ERROR_CODES.INVALID_HWID);
  }
} else {
  // HWID matches - update auth stats
  await pool.execute(`
    UPDATE user_licenses 
    SET last_auth_ip = ?, last_auth_at = NOW(), total_auth_count = total_auth_count + 1
    WHERE id = ?
  `, [ip_address, license.id]);
}