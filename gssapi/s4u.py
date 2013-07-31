from __future__ import print_function
import gssapi.base as gb

from gssapi.type_wrappers import GSSName
from gssapi.type_wrappers import GSSContext
from gssapi.type_wrappers import GSSCredentials

is_string = None

try:
    is_string = lambda x: isinstance(x, basestring)
except NameError:
    is_string = lambda x: isinstance(x, str) or isinstance(x, bytes)

class GSSDelegatorProxy(object):
    """
    S4U Delegator Proxy

    This class implements all functionality to create a basic
    service which uses S4U2Self and S4U2Proxy to perform constrained
    delegation of access to another service

    :param target_service: the service to which this Proxy connects
                           on behalf of the user
    :type target_service: str/bytes, :class:`gssapi.type_wrappers.GSSName`,
                          or PyCapsule

    .. warning::
       
       All methods in this class can potentially raise
       :class:`gssapi.base.types.GSSError`

    .. note::
       
       Below, "Autogen" means that a given attribute will be automatically
       initialized based on current state the first time it is used, if not
       already assigned.
    
    .. attribute:: target_service
        
       Read Type: GSSName
       Access: Read
       Autogen: False

       The service to which the proxy connects on behalf of the user

    .. attribute:: proxy_credentials
       
       Read Type: PyCapsule
       Access: Read
       Autogen: True

       The basic credentials for the proxy.  Should have
       both accept and initiate usage permissions.

    .. attribute:: proxy_name_self
        
       Read Type: GSSName
       Write Type: str/bytes, GSSName, or PyCapsule
       Access: Read/Write
       Autogen: True

       The name of the proxy service itself, used to initialize
       :attr:`proxy_credentials`, among other things

    .. attribute:: proxy_name_target

       Read Type: GSSName
       Write Type: str/bytes, GSSName, or PyCapsule
       Access: Read/Write
       Autogen: True

       The name of the proxy service as a target hostbased
       service, for use in the S4U2Self

    .. attribute:: impersonated_credentials
       
       Read Type: PyCapsule
       Access: Read
       Autogen: True

       The service's credentials impersonating the user

    .. attribute:: delegated_credentials
       
       Read Type: PyCapsule
       Access: Read
       Autogen: True

       The delegated credentials from the user to connect to
       the target service

    .. attribute:: initiator_name
       
       Read Type: GSSName
       Write Type: str/bytes, GSSName, or PyCapsule
       Access: Read/Write
       Autogen: False

       The user's name.  This can be initiated by using the acceptor
       code, or set manually

    .. attribute:: client_uses_encryption

       Read Type: bool
       Write Type: bool
       Access: Read/Write
       Autogen: False
       Default Value: True

       Whether or not the client uses encryption.

    .. attribute:: service_uses_encryption

       Read Type: bool
       Write Type: bool
       Access: Read/Write
       Autogen: False
       Default Value: True

       Whether or not the target service uses encryption.

    .. attribute:: client_uses_integrity

       Read Type: bool
       Write Type: bool
       Access: Read/Write
       Autogen: False
       Default Value: True

       Whether or not the client uses integrity (implied to
       be True if client_uses_encryption is True)

    .. attribute:: service_uses_integrity

       Read Type: bool
       Write Type: bool
       Access: Read/Write
       Autogen: False
       Default Value: True

       Whether or not the target service uses integrity (implied
       to be True if service_uses_encryption is True).

    """

    def __init__(self, target_service):
            self.target_service = GSSName.create_if_needed(target_service)
            self._proxy_credentials = None
            self._impersonated_credentials = None
            self._delegated_credentials = None
            self.proxy_name_self = None
            self.proxy_name_target = None
            self._initiator_name = None
            self.c2p_ctx = None
            self.p2s_ctx = None
            self.client_uses_encryption = True
            self.client_uses_integrity = True
            self.service_uses_encryption = True
            self.service_uses_integrity = True

    def _get_proxy_credentials(self):
        if self._proxy_credentials is None:
            print("DEBUG: acquiring proxy credentials")
            self._proxy_credentials = GSSCredentials.acquire(self.proxy_name_self,
                                                             cred_usage='both')
        return self._proxy_credentials

    def _set_proxy_credentials(self, creds):
        self._proxy_credentials = creds

    proxy_credentials = property(_get_proxy_credentials,
                                 _set_proxy_credentials)

    @property
    def impersonated_credentials(self):
        if self._impersonated_credentials is None:
            print("DEBUG: acquiring impersonated credentials")
            self._impersonated_credentials = self.proxy_credentials.impersonate(self.initiator_name)

        return self._impersonated_credentials

    @property
    def delegated_credentials(self):
        if self._delegated_credentials is None:
            print("DEBUG: acquiring delegated credentials")
            to_self = GSSContext.initiate_new(self.proxy_name_target,
                                              cred=self.impersonated_credentials)
            to_self_tok = to_self.token
            del to_self  # free all the things!

            from_self = GSSContext.accept_new(to_self_tok,
                                              acceptor_cred=self.proxy_credentials)

            self._delegated_credentials = from_self.delegated_credentials
            del from_self  # clear all the things, again!

        return self._delegated_credentials

    def _get_initiator_name(self):
        if self._initiator_name is None:
            self._initiator_name = self.c2p_ctx.initiator_name
        return self._initiator_name

    def _set_initiator_name(self, name):
        self._initiator_name = GSSName.create_if_needed(name)

    initiator_name = property(_get_initiator_name,
                              _set_initiator_name)

    def __del__(self):
        # TODO(sross): free contexts and creds here
        pass

    def accept_c2p_context(self, token):
        print("DEBUG: accepting context")
        if self.c2p_ctx is None:
            self.c2p_ctx = GSSContext.accept_new(token,
                                                 acceptor_cred=self.proxy_credentials)
        else:
            self.c2p_ctx.accept(token, acceptor_cred=self.proxy_credentials)

        return (self.c2p_ctx.token, self.c2p_ctx.continue_needed)

    def initiate_p2s_context(self, token=None):
        print("DEBUG: initiating context")
        if self.p2s_ctx is None:
            self.p2s_ctx = GSSContext.initiate_new(self.target_service,
                                                   cred=self.delegated_credentials,
                                                   input_token=token,
                                                   mech_type=gb.MechType.kerberos)
        else:
            self.p2s_ctx.initiate(self.target_service,
                                  cred=self.delegated_credentials,
                                  input_token=token,
                                  mech_type=gb.MechType.kerberos)

        return (self.p2s_ctx.token, self.p2s_ctx.continue_needed)

    def wrap(self, msg, to):
        """
        Wrap a message to a either the client or target service.
        """
        if to == 'client':
            if (not self.client_uses_encryption and
                    not self.client_uses_integrity):
                return msg
            else:
                return gb.wrap(self.c2p_ctx, msg,
                               confidential=self.client_uses_encryption)[0]
        else:
            if (not self.service_uses_encryption and
                    not self.service_uses_integrity):
                return msg
            else:
                return gb.wrap(self.p2s_ctx, msg,
                               confidential=self.service_uses_encryption)[0]

    def unwrap(self, msg, frm):
        """
        Unwrap a message from either the client or target service.
        """
        if frm == 'client':
            if (not self.client_uses_encryption and
                    not self.client_uses_integrity):
                return msg
            else:
                return gb.unwrap(self.c2p_ctx, msg)[0]
        else:
            if (not self.service_uses_encryption and
                    not self.service_uses_integrity):
                return msg
            else:
                return gb.unwrap(self.p2s_ctx, msg)[0]

    def repackage(self, msg, frm):
        if frm == 'client':
            dec_msg = self.unwrap(msg, frm='client')
            return self.wrap(dec_msg, to='service')
        else:
            dec_msg = self.unwrap(msg, frm='service')
            return self.wrap(dec_msg, to='client')
