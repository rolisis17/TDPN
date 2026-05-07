//go:build windows

package issuer

import (
	"testing"

	"golang.org/x/sys/windows"
)

func restrictIssuerTestSecretFile(t *testing.T, path string) {
	t.Helper()

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("get current user SID: %v", err)
	}
	ownerSID := user.User.Sid
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatalf("create system SID: %v", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatalf("create administrators SID: %v", err)
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		issuerTestFullControlACE(ownerSID, windows.TRUSTEE_IS_USER),
		issuerTestFullControlACE(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		issuerTestFullControlACE(adminSID, windows.TRUSTEE_IS_ALIAS),
	}, nil)
	if err != nil {
		t.Fatalf("build test secret ACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("apply test secret ACL: %v", err)
	}
}

func issuerTestFullControlACE(sid *windows.SID, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
