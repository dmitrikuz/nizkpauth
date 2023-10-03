class Hash:
    def __init__(self, name):
        self.__config = HASH_PRESETS[name]

    @property
    def name(self):
        return self.__config['name']
    
    @property
    def size(self):
        return self.__config['size']
    
    @property
    def salt(self):
        ...



HASH_PRESETS = {
    'sha256' : {"name": "sha256", "size": 256},
    'sha384' : {"name": "sha384", "size": 384},
    'sha224' : {"name": "sha224", "size": 224},
}