import json
import urllib.request
import urllib.parse
import urllib.error
import base64
import openssl
import time
import binascii

# Ceci est du code Python v3.x (la version >= 3.4 est conseillée pour une
# compatibilité optimale).
# --- les admins

def init():
    return Connection()

class ServerError(Exception):
    """
    Exception déclenchée en cas de problème côté serveur (URL incorrecte,
    accès interdit, requête mal formée, etc.)
    """
    def __init__(self, code=None, msg=None):
        self.code = code
        self.msg = msg


class Connection:
    """
    Cette classe sert à ouvrir et à maintenir une connection avec le système
    UGLIX. Voir les exemples ci-dessous.

    Pour créer une instance de la classe, il faut spécifier une ``adresse de 
    base''. Les requêtes se font à partir de là, ce qui est bien pratique.
    L'adresse de base est typiquement l'adresse du système UGLIX.

    Cet objet Connection() s'utilise surtout via ses méthodes get(), post()...

    Il est conçu pour pouvoir être étendu facilement. En dériver une sous-classe
    capable de gérer des connexions chiffrées ne nécessite que 20 lignes de
    code supplémentaires.

    Exemple :
    >>> c = Connection("http://pac.fil.cool/uglix")
    >>> c.get('/bin/echo')
    'usage: echo [arguments]'
    """
    def __init__(self, base_url='http://pac.fil.cool/uglix'):
        self.base = base_url
        # au départ nous n'avons pas d'identifiant de session
        self.session = None

    def _post_processing(self, result, http_headers):
        """
        Effectue post-traitement sur le résultat "brut" de la requête. En
        particulier, on décode les dictionnaires JSON, et on converti le texte
        encodé en UTF-8 en chaine de charactère Unicode. On peut étendre Cette
        méthode pour gérer d'autres types de contenu si besoin.
        """
        if http_headers['Content-Type'] == "application/json":
            return json.loads(result.decode())
        if http_headers['Content-Type'].startswith("text/plain"):
            return result.decode()
        # on ne sait pas ce que c'est : on tel quel
        return result

    def _query(self, url, request, data=None):
        """
        Cette fonction à usage interne est appelée par get(), post(), put(),
        etc. Elle reçoit en argument une url et un
        """
        try:
            # si on a un identifiant de session, on le renvoie au serveur
            if self.session:
                request.add_header('Cookie', self.session)
            # lance la requête. Si data n'est pas None, la requête aura un
            # corps non-vide, avec data dedans.
            with urllib.request.urlopen(request, data) as connexion:
                # récupère les en-têtes HTTP et le corps de la réponse, puis
                # ferme la connection
                headers = dict(connexion.info())
                result = connexion.read()
            
            # si on envoie un identifiant de session, on le stocke
            if 'Set-Cookie' in headers:
                self.session = headers['Set-Cookie']

            # on effectue le post-processing, puis on renvoie les données.
            # c'est fini.
            return self._post_processing(result, headers)

        except urllib.error.HTTPError as e:
            # On arrive ici si le serveur a renvoyé un code d'erreur HTTP
            # (genre 400, 403, 404, etc.). On récupère le corps de la réponse
            # car il y a peut-être des explications dedans. On a besoin des
            # en-tête pour le post-processing.
            headers = dict(e.headers)
            message = e.read()
            return self._post_processing(message, headers)
          
    
    def get(self, url):
        """
        Charge l'url demandée. Une requête HTTP GET est envoyée.

        >>> c = Connection("http://pac.fil.cool/uglix")
        >>> c.get('/bin/echo')
        'usage: echo [arguments]'

        En cas d'erreur côté serveur, on récupère une exception.
        >>> c.get('/bin/foobar') # doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        client.ServerError: (404, ...)
        """
        # prépare la requête
        request = urllib.request.Request(self.base + url, method='GET')
        return self._query(url, request)


    def post(self, url, **kwds):
        """
        Charge l'URL demandée. Une requête HTTP POST est envoyée. Il est 
        possible d'envoyer un nombre arbitraire d'arguments supplémentaires
        sous la forme de paires clef-valeur. Ces paires sont encodées sous la
        forme d'un dictionnaire JSON qui constitue le corps de la requête.

        Python permet de spécifier ces paires clef-valeurs comme des arguments
        nommés de la méthode post(). On peut envoyer des valeurs de n'importe
        quel type sérialisable en JSON.

        Par exemple, pour envoyer un paramètre nommé "string_example" de valeur
        "toto et un paramètre nommé "list_example" de valeur [True, 42, {'foo': 'bar'}],
        il faut invoquer :

        >>> c = Connection("http://pac.fil.cool/uglix")
        >>> c.post('/bin/echo', string_example="toto", list_example=[True, 42, {'foo': 'bar'}])
        {'content_found': {'string_example': 'toto', 'list_example': [True, 42, {'foo': 'bar'}]}}

        L'idée la méthode post() convertit ceci en un dictionnaire JSON, qui 
        ici ressemblerait à :

        {'string_example': 'toto', 'list_example': [True, 42, {'foo': 'bar'}]},

        puis l'envoie au serveur.
        """
        # prépare la requête
        request = urllib.request.Request(self.base + url, method='POST')
        data = None
        # kwds est un dictionnaire qui contient les arguments nommés. S'il
        # n'est pas vide, on l'encode en JSON et on l'ajoute au corps de la
        # requête.
        if kwds:     
            request.add_header('Content-type', 'application/json')
            data = json.dumps(kwds).encode()
        return self._query(url, request, data)


    def put(self, url, content):
        """
        Charge l'URL demandée avec une requête HTTP PUT. L'argument content
        forme le corps de la requête. Si content est de type str(), il est
        automatiquement encodé en UTF-8. cf /doc/strings pour plus de détails
        sur la question.
        """
        request = urllib.request.Request(self.base + url, method='PUT')
        if type(content) == str:
            content = content.encode()
        return self._query(url, request, data=content)


    def post_raw(self, url, data, content_type='application/octet-stream'):
        """
        Charge l'url demandée avec une requête HTTP POST. L'argument data
        forme le corps de la requête. Il doit s'agir d'un objet de type 
        bytes(). Cette méthode est d'un usage plus rare, et sert à envoyer des
        données qui n'ont pas vocation à être serialisées en JSON (comme des
        données binaires chiffrées, par exemple).

        Principalement utilisé pour étendre le client et lui ajouter des
        fonctionnalité.
        """
        request = urllib.request.Request(self.base + url, method='POST')
        request.add_header('Content-type', content_type)
        return self._query(url, request, data)

    def chap(self):
        challenge = self.get('/bin/login/CHAP')['challenge']
        password = "+*aX7*md&L"
        login = "carolina85"
        crypt = openssl.encrypt(login + '-' + challenge, password)
        self.post('/bin/login/CHAP', user=login, response=crypt)

    def otp(self):
        a = base64.b64decode(self.get('/bin/police_hq/ticket/241/attachment/exhibit-A'))
        b = base64.b64decode(self.get('/bin/police_hq/ticket/241/attachment/exhibit-B'))
        myarray = bytearray()
        for i, j in zip(a, b):
            myarray.append(i ^ j)
        rep = bytearray()
        for ch in myarray:
            rep.append((ch ^ ord('0')))
        rep2 = bytearray()
        for ch in myarray:
            rep2.append((ch ^ ord('1')))
        print (rep2)
        return rep

    def verify_transaction(self, cb):
        ca = self.get('/bin/banks/CA')
        info = self.get('/bin/banks/card-data/' + cb)
        if openssl.verify_certif(ca, info['bank-certificate'], info['card-certificate']) != 'ut2: OK\n':
            return False
        if openssl.verify_challenge(info['challenge'], info['card-certificate'], info['signature']) != 'Verified OK\n':
            return False
        if info['bank-name'] not in openssl.getText(info['bank-certificate']):
            return False
        if info['bank-name'] not in openssl.getText(info['card-certificate']):
            return False
        if info['card-number'] not in openssl.getText(info['card-certificate']):
            return False
        return True

    def transactions(self):
        t = self.get('/bin/banks/forensics')
        statuses = []
        for card in t['card-numbers']:
            statuses.append(self.verify_transaction(card))
        return {'identifier':t['identifier'], 'statuses':statuses}

    def authenti(self, password):
        login = "carolina85"
        d = {'username':login, 'timestamp':time.time()}
        e = json.dumps(d)
        f = openssl.encrypt(e, password)
        return f

    def service(self, name):
        login = "carolina85"
        password = "+*aX7*md&L"
        d = self.post('/bin/kerberos/authentication-service', username=login)
        key = openssl.decrypt(d['Client-TGS-session-key'], password)
        token = self.authenti(key)
        d = self.post('/bin/kerberos/ticket-granting-service', TGT=d['TGT'], service=name, authenticator=token)
        key = openssl.decrypt(d['Client-Server-session-key'], key)
        d = self.post('/service/' + name + '/hello', ticket=d['Client-Server-ticket'], authenticator=self.authenti(key))
        self.service_key = key
        return d

    def srequest(self, method, url, args, service):
        data = json.dumps({'method':method, 'url':url, 'args': args}).encode()
        crypt = openssl.encrypt(data, self.service_key)
        res = self.post_raw('/service/' + service + '/request', binascii.a2b_base64(crypt))
        return openssl.decrypt_service(res, self.service_key)
                                          
    def gateway(self):
        dico = {'method':'PUT', 'url':'/bin/echo', 'data':'VsOkaW7Dtg=='}
        data = openssl.encrypt(json.dumps(dico, 'debug-me').encode(), 'debug-me')
        retour = self.post_raw('/bin/test-gateway', binascii.a2b_base64(data))

        return openssl.decrypt_service(retour, 'debug-me')

    def reverse_f(self, y):
        k1 = 4022730752
        k2 = 2636928640
        x1 = (y >> 14) << 14 # 18 bits poids fort
        x1 |= ((x1 >> 18) & 0x3FFF) ^ (y & 0x3FFF)
        #x2 = (x1 << 17) >> 17 # 15 bits poids faible
        #x2 |= (x2 & k1) ^ (((x1 << 2) >> 17) << 15) # 15 bits suivants
        #x2 |= ((x2 >> 30) << 30) ^ ((((x1 >> 15) << 30) >> 15) & k1) # 2 bits poids fort
        #x3 = x2
        #print (x1)
        #print (x2)
        return x1

    def _f(self, y):
        y ^= y >> 11
        print(y)
        y ^= (y << 7) & 2636928640
        print(y)
        y ^= (y << 15) & 4022730752
        print(y)
        y ^= y >> 18
        return y
