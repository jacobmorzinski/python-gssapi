from __future__ import print_function
import gssapi.base as gss
import struct
import sys
from gssapi.type_wrappers import GSSName


def debug(p, v):
    print("{0}: {1}".format(p.upper(), v), file=sys.stderr)


class GSSClientError(Exception):
    """
    GSS Client Error

    This Exception represents an error which occured
    when executing the GSS Client code (as opposed to
    :class:`gssapi.base.types.GSSError`, which are errors
    which occured directly in the GSSAPI C code).
    """
    pass


class BasicGSSClient(object):
    """
    Basic GSS Client

    This class implements all functionality needed to initialize a basic
    GSS connection and send/receive encrypted or signed messages.

    :param str target: the service name to which to connect
                       (automatically converted to a
                        :class:`gssapi.type_wrappers.GSSName`),
                       should be a host-based service name
    :param dbg: a method for printing debug messages (not currently used)
    :type dbg: function(title, message)
    :param security_type: the level of security to use
    :type security_type: str containing enc(crypted)/conf(idential),
                         integ(rity) or any, or just None
    :param max_msg_size: the maximum message size for encryption/decryption
    :type max_msg_size: int > 0 or None (for default)

    .. warning::

       All methods in this class can potentially raise
       :class:`gssapi.base.types.GSSError`

    .. attribute:: service_name

       The service name to which we are connecting
       (as a :class:`gssapi.type_wrappers.GSSName`)

    .. attribute:: ctx

       Type: Capsule

       The internal GSS context object

    .. attribute:: token

       Type: bytes

       The last returned token from one of the token-manipulation methods

    .. attribute:: ttl

       Type: int >= 0

       The desired time-to-live for the GSS context object

    .. attribute:: last_ttl

       Type: int > 0

       The actual amount of time for which the current
       GSS context object will be valid

    .. attribute:: flags

       Type: [:class:`gssapi.base.types.RequirementFlag`]

       The flags to use when creating the GSS context

    .. attribute:: channel_bindings

       Type: TBD or None

       .. warning::

          Not Currently Implemented

    .. attribute:: mech_type

       Type: MechanismType or None

       Represents the desired mechanism type to be used
       (None uses the default type).

    """

    def __init__(self, target,
                 security_type='encrypted', max_msg_size=None):

        self.service_name = GSSName(target)
        self.ctx = None
        self.token = None
        self.ttl = 0
        self.last_ttl = None
        self.channel_bindings = None
        self.mech_type = None
        self.flags = [gss.RequirementFlag.mutual_authentication,
                      gss.RequirementFlag.out_of_sequence_detection]

        if security_type[0:5] == 'integ':
            self.security_type = gss.RequirementFlag.integrity
            self.flags.append(self.security_type)
        elif security_type[0:4] == 'conf' or security_type[0:3] == 'enc':
            self.security_type = gss.RequirementFlag.confidentiality
            self.flags.append(self.security_type)
            self.flags.append(gss.RequirementFlag.integrity)
        elif security_type == 'any':
            self.security_type = None
        else:
            self.security_type = 0

    def setupBaseSecurityContext(self):
        """
        Initializes a default token and security context

        This method gets and returns a default token, and
        initializes the corresponding security context

        :rtype: bytes
        :returns: the token created in the process of
                  initializing the security context
        """

        resp = gss.initSecContext(self.service_name,
                                  flags=self.flags,
                                  mech_type=self.mech_type,
                                  ttl=self.ttl)

        (self.ctx, _, _, self.token, self.last_ttl, _) = resp
        return self.token

    def updateSecurityContext(self, server_tok):
        """
        Processes a server token, and updates the security context

        This method processes a server token, updates the internal
        security context, and returns the new resulting token.

        :param bytes server_tok: the token sent from the server
        :rtype: bytes
        :returns: the token resulting from updating the security context
        """

        resp = gss.initSecContext(self.service_name,
                                  context=self.ctx,
                                  input_token=server_tok,
                                  flags=self.flags,
                                  mech_type=self.mech_type,
                                  ttl=self.ttl)

        (self.ctx, _, _, self.token, self.last_ttl, _) = resp
        return self.token

    def encrypt(self, str_msg):
        """
        Encrypts a message

        This method encrypts a message according to the current
        security level

        :param str msg: the message to be encrypted
        :rtype: bytes
        :returns: the encrypted form of the message
        :except GSSClientError: if the requested security level
                                could not be used
        """
        msg = str_msg.encode('utf-8')
        if self.security_type == gss.RequirementFlag.integrity:
            return gss.wrap(self.ctx, msg, False, None)[0]
        elif self.security_type == gss.RequirementFlag.confidentiality:
            res, used = gss.wrap(self.ctx, msg, True, None)
            if not used:
                raise GSSClientError('User requested encryption, '
                                     'but it was not used!')
            return res
        else:
            return msg

    def decrypt(self, msg):
        """
        Decrypts a message

        This method decrypts a message encrypted by the server.

        :param bytes msg: the message to be decrypted
        :rtype: str
        :returns: the decrypted message
        :except GSSClientError: if encryption was requested but not used,
                or if the QoP failed to meet our standards
        """
        if self.security_type is not None and self.security_type != 0:
            res, used, _ = gss.unwrap(self.ctx, msg)
            isconf = self.security_type == gss.RequirementFlag.confidentiality
            if (not used and isconf):
                raise GSSClientError('User requested encryption, '
                                     'but the server sent an unencrypted '
                                     'message!')
            return res.decode('utf-8')
        else:
            return msg.decode('utf-8')

    def __del__(self):
        if self.ctx is not None:
            gss.deleteSecContext(self.ctx)


class SASLGSSClientError(GSSClientError):
    """
    SASL GSS Client Error

    This Exception represents an error which occured
    when executing the SASL GSS Client helper code (as opposed to
    :class:`gssapi.base.types.GSSError`, which are errors which
    occured directly in the GSSAPI C code).
    """
    pass


class BasicSASLGSSClient(BasicGSSClient):
    """
    A helper for using the SASL GSSAPI mechanism

    This class contains helper code to support implementing
    the SASL GSSAPI mechanism using PyGSSAPI.

    All parameters besides username are used as in :class:`BasicGSSClient`.
    All relevant attributes are set according to the SASL GSSAPI RFC
    (http://tools.ietf.org/html/rfc4752).

    :param str username: the user name with which to authenticate

    .. attribute:: user_name

       The username to use in the authentication process

       .. warning::

          Unlike :attr:`service_name`, this is just a string,
          not a :class:`gssapi.type_wrappers.GSSName`
    """

    def __init__(self, username, target,
                 max_msg_size=None, *args, **kwargs):

        self.user_name = username
        self.max_msg_size = max_msg_size
        super(BasicSASLGSSClient, self).__init__(target,
                                                 *args, **kwargs)

        self.channel_bindings = None
        self.resolveMechType(gss.MechType.kerberos)

        self.INV_SEC_LAYER_MASKS = {v: k
                                    for k, v
                                    in self.SEC_LAYER_MASKS.items()}

    def step1(self):
        """
        Creates a default token

        This method is step 1 in the SASL process, and
        creates a default token

        :rtype: bytes
        :returns: a default token to send to the server
        """
        return self.setupBaseSecurityContext()

    def step2(self, server_tok):
        """
        Processes a server token

        This method is step 2 in the SASL process, and
        processes a server token

        :param bytes server_tok: the token returned from the server
        :rtype: bytes
        :returns: a token or empty string to be sent to the server
        """
        return self.updateSecurityContext(server_tok)

    SEC_LAYER_MASKS = {
        0: 1,
        int(gss.RequirementFlag.integrity): 2,
        int(gss.RequirementFlag.confidentiality): 4
    }

    INV_SEC_LAYER_MASKS = None

    def step3(self, tok):
        """
        Deals with SSF

        This method deals with negotiating SSF (the security level)
        and max message size, setting the max message size appropriately

        :param bytes tok: the wrapped message sent from the server
        :rtype: bytes
        :returns: a wrapped message to be sent to the server declaring
                  our security level and max message size
        """

        # we don't care out security for this,
        # so we don't use self.unwrap
        unwrapped_tok = gss.unwrap(self.ctx, tok)[0]
        sec_layers_supported_raw = ord(unwrapped_tok[0])
        max_server_msg_size_raw = '\x00' + unwrapped_tok[1:4]
        max_server_msg_size = struct.unpack('!L', max_server_msg_size_raw)[0]

        if (self.max_msg_size is None
                or self.max_msg_size > max_server_msg_size):

            self.max_msg_size = max_server_msg_size

        sec_layers_supported = []
        for name, mask in self.SEC_LAYER_MASKS.items():
            if sec_layers_supported_raw & mask > 0:
                sec_layers_supported.append(name)

        sec_layer_choice = 0
        if self.security_type == 'any':
            for mask in self.SEC_LAYER_MASKS.values():
                if mask & sec_layers_supported_raw > sec_layer_choice:
                    sec_layer_choice = mask
        elif self.security_type in sec_layers_supported:
            sec_layer_choice = self.SEC_LAYER_MASKS[self.security_type]
        else:
            raise SASLGSSClientError('Server is unable to accomodate '
                                     'our security level!')

        if self.security_layer is None:
            self.security_layer = self.INV_SEC_LAYER_MASKS[sec_layer_choice]

        resp = (chr(sec_layer_choice) +
                struct.pack('!L', self.max_msg_size)[0:3] +
                self.user_name)

        # again, we don't care about our selected security type for this one
        return gss.wrap(self.ctx, resp, False, None)[0]
