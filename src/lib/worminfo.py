import datetime
from ctypes import *
from wormtypes import *


class Worm_Info:
    def __init__(self, worm):
        self.ctx = worm.ctx
        self.wormlib = worm.wormlib

        self.wormlib.worm_info_new.argtypes = (WormContext,)
        self.wormlib.worm_info_new.restype = WormInfo
        self.info = cast(self.wormlib.worm_info_new(self.ctx), WormInfo)
        self.wormlib.worm_info_read.restype = WormError
        self.wormlib.worm_info_read.argtypes = (WormInfo,)
        self.update()

    def update(self):
        self.wormlib.worm_info_read(self.info)

    def __del__(self):
        if self.info:
            self.wormlib.worm_info_free(self.info)
            self.info = None

    def __getattr__(self, key):
        # bool-Attribute (uint32, als bool zurückgegeben)
        if key in [
            'isDevelopmentFirmware', 'isTSEv2',
            'hasValidTime', 'hasPassedSelfTest',
            'isCtssInterfaceActive', 'isErsInterfaceActive',
            'isExportEnabledIfCspTestFails',
            'isDataImportInProgress', 'isTransactionInProgress',
            # PUK/PIN-Änderungsstatus
            'hasChangedAdminPuk', 'hasChangedPuk',          # hasChangedPuk = deprecated alias
            'hasChangedTimeAdminPuk', 'hasChangedLoggerPuk',
            'hasChangedAdminPin', 'hasChangedTimeAdminPin', 'hasChangedLoggerPin',
        ]:
            return bool(self.__get_info_uint32(key))

        # uint64-Attribute
        elif key in ['tarExportSizeInSectors', 'tarExportSize']:
            return self.__get_info_uint64(key)

        # uint32-Attribute
        elif key in [
            'size', 'capacity',
            'timeUntilNextSelfTest', 'timeUntilNextTimeSynchronization',
            'startedTransactions', 'maxStartedTransactions',
            'createdSignatures', 'maxSignatures', 'remainingSignatures',
            'maxTimeSynchronizationDelay', 'maxUpdateDelay',
            'registeredClients', 'maxRegisteredClients',
            'initializationState',
            # TSE v2: PUK-Blocking-Dauer (0 = nicht geblockt, >0 = Sekunden geblockt)
            'pukBlockingDurationAdmin', 'pukBlockingDurationTimeAdmin', 'pukBlockingDurationLogger',
            # TSE v2: aktuell eingeloggter Benutzer (WormUserId-Enum-Wert)
            'loggedInUser',
        ]:
            return self.__get_info_uint32(key)

        # uint16-Attribute
        elif key in ['loggedInUserAutoLogOutTimeout']:
            return self.__get_info_uint16(key)

        # String-Attribute (const char*, NULL-terminiert)
        elif key in [
            'customizationIdentifier', 'uniqueId',   # uniqueId deprecated, nutze tseSerialNumber
        ]:
            return self.__get_string(key)

        # binary Attribute (Byte-Buffer via Längenzeiger)
        elif key in ['tsePublicKey', 'tseSerialNumber']:
            return self.__get_string64(key)

        # char*-Attribute (NULL-terminierter String, kein Längenzeiger)
        elif key in [
            'tseCertificationId',   # SDK v6: ersetzt tseDescription
            'tseDescription',       # deprecated alias für tseCertificationId
            'formFactor',
        ]:
            return self.__get_chars(key)

        # Versions-Tupel (major, minor, patch)
        elif key in ['softwareVersion', 'hardwareVersion']:
            return self.__get_version(key)

        # Datum (Unix-Timestamp → datetime)
        elif key in ['certificateExpirationDate']:
            return self.__get_date(key)

        else:
            raise AttributeError('unimplemented: %s' % key)

    # ── private Getter ──────────────────────────────────────────────────────

    def __get_info_uint64(self, key):
        fn = getattr(self.wormlib, 'worm_info_' + key)
        fn.restype = c_uint64
        fn.argtypes = (WormInfo,)
        return fn(self.info)

    def __get_info_uint32(self, key):
        fn = getattr(self.wormlib, 'worm_info_' + key)
        fn.restype = c_uint32
        fn.argtypes = (WormInfo,)
        return fn(self.info)

    def __get_info_uint16(self, key):
        fn = getattr(self.wormlib, 'worm_info_' + key)
        fn.restype = c_uint16
        fn.argtypes = (WormInfo,)
        return fn(self.info)

    def __get_chars(self, key):
        fn = getattr(self.wormlib, 'worm_info_' + key)
        fn.restype = c_char_p
        fn.argtypes = (WormInfo,)
        ret = fn(self.info)
        return ret.decode('latin1') if ret else ''

    def __get_string(self, key):
        s = c_char_p()
        sLength = c_uint()
        fn = getattr(self.wormlib, 'worm_info_' + key)
        fn.argtypes = (WormInfo, POINTER(c_char_p), POINTER(c_uint))
        fn(self.info, byref(s), byref(sLength))
        s = cast(s, POINTER(c_char))
        return string_at(s, size=sLength.value)

    def __get_string64(self, key):
        s = c_char_p()
        sLength = c_uint64()
        fn = getattr(self.wormlib, 'worm_info_' + key)
        fn.argtypes = (WormInfo, POINTER(c_char_p), POINTER(c_uint64))
        fn(self.info, byref(s), byref(sLength))
        s = cast(s, POINTER(c_char))
        return string_at(s, size=sLength.value)

    def __get_version(self, key):
        fn = getattr(self.wormlib, 'worm_info_' + key)
        fn.restype = c_uint32
        fn.argtypes = (WormInfo,)
        ret = fn(self.info)
        major = (ret & 0xFFFF0000) >> 16
        minor = (ret & 0x0000FF00) >> 8
        patch = (ret & 0x000000FF)
        return (major, minor, patch)

    def __get_date(self, key):
        fn = getattr(self.wormlib, 'worm_info_' + key)
        fn.restype = c_uint64
        fn.argtypes = (WormInfo,)
        ret = fn(self.info)
        return datetime.datetime.fromtimestamp(ret)
