class FGError(Exception):
    code = "E_GENERIC"
    def __init__(self, message=""):
        super().__init__(message or self.code)

class EVersion(FGError):      code = "E_VERSION"
class EFlags(FGError):        code = "E_FLAGS"
class EArmor(FGError):        code = "E_ARMOR"
class EKeyfile(FGError):      code = "E_KEYFILE"
class EDecrypt(FGError):      code = "E_DECRYPT"
class ESig(FGError):          code = "E_SIG"
class ELexicon(FGError):      code = "E_LEXICON"
