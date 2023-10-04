from nizkpauth.exceptions import InvalidHashName

class Hash:
    def __init__(self, name):
        self._set_config(name)


    def _set_config(self, name):
        try:
            self._config = HASH_PRESETS[name]
        except KeyError as e:
            raise InvalidHashName
        
    @property
    def name(self):
        return self._config['name']
    
    @property
    def size(self):
        return self._config['size']
    
    @property
    def salt(self):
        ...



HASH_PRESETS = {
    'sha256' : {"name": "sha256", "size": 256},
    'sha384' : {"name": "sha384", "size": 384},
    'sha224' : {"name": "sha224", "size": 224},
}