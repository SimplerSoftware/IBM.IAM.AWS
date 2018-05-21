using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    internal class ImpersonationState : IDisposable
    {
        public IntPtr TokenHandle { get; private set; }

        public IntPtr DuplicatedTokenHandle { get; private set; }

        public WindowsImpersonationContext ImpersonationContext { get; private set; }

        private ImpersonationState()
        {
        }

        [SecuritySafeCritical]
        public static ImpersonationState Impersonate(NetworkCredential networkCredential)
        {
            IntPtr zero = IntPtr.Zero;
            IntPtr zero2 = IntPtr.Zero;
            if (!NativeMethods.LogonUser(networkCredential.UserName, networkCredential.Domain, networkCredential.Password, 9, 3, ref zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (!NativeMethods.DuplicateToken(zero, 2, ref zero2))
            {
                NativeMethods.CloseHandle(zero);
                return null;
            }
            WindowsIdentity windowsIdentity = new WindowsIdentity(zero2);
            return new ImpersonationState
            {
                TokenHandle = zero,
                DuplicatedTokenHandle = zero2,
                ImpersonationContext = windowsIdentity.Impersonate()
            };
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        [SecuritySafeCritical]
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (this.ImpersonationContext != null)
                {
                    this.ImpersonationContext.Undo();
                }
                if (this.TokenHandle != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(this.TokenHandle);
                    this.TokenHandle = IntPtr.Zero;
                }
                if (this.DuplicatedTokenHandle != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(this.DuplicatedTokenHandle);
                    this.DuplicatedTokenHandle = IntPtr.Zero;
                }
            }
        }
    }
}
