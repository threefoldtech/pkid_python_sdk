import pkid

from mnemonic import Mnemonic

node_url = "https://pkid.staging.jimber.org"

_mnemonic = Mnemonic("english")

seed_phrase = "govern exact air mountain album symbol tobacco pigeon sunset curtain identify search company bullet consider drip blame invite switch suggest alcohol galaxy never ugly"
entropy_bytes = bytes(_mnemonic.to_entropy(seed_phrase))

_pkid = pkid.Pkid(node_url, entropy_bytes)

set_response = _pkid.set_document("pokemon", "pikachu", is_encrypted = True)
get_response = _pkid.get_document("pokemon")

print(set_response)
print(get_response)