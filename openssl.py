from subprocess import Popen, PIPE
import base64

# en cas de problème, cette exception est déclenchée
class OpensslError(Exception):
    pass


def encrypt(plaintext, passphrase, cipher='aes-128-cbc'):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to encrypt content using a symmetric cipher.

       The passphrase is an str object (a unicode string)
       The plaintext is str() or bytes()
       The output is bytes()

       # encryption use
       >>> message = "texte avec caractères accentués"
       >>> c = encrypt(message, 'foobar')
       
    """
    # prépare les arguments à envoyer à openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-' + cipher, '-base64', '-pass', pass_arg]
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return stdout.decode()

def encrypt_service(plaintext, passphrase, cipher='aes-128-cbc'):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to encrypt content using a symmetric cipher.

       The passphrase is an str object (a unicode string)
       The plaintext is str() or bytes()
       The output is bytes()

       # encryption use
       >>> message = "texte avec caractères accentués"
       >>> c = encrypt(message, 'foobar')
       
    """
    # prépare les arguments à envoyer à openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-' + cipher, '-pass', pass_arg]
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return stdout

def decrypt(plaintext, passphrase, cipher='aes-128-cbc'):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to encrypt content using a symmetric cipher.

       The passphrase is an str object (a unicode string)
       The plaintext is str() or bytes()
       The output is bytes()

       # encryption use
       >>> message = "texte avec caractères accentués"
       >>> c = encrypt(message, 'foobar')
       
    """
    # prépare les arguments à envoyer à openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-d', '-' + cipher, '-base64', '-pass', pass_arg]
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        return ''
    #    raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    try:
        return stdout.decode()
    except UnicodeError:
        return ''

def decrypt_service(plaintext, passphrase, cipher='aes-128-cbc'):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to encrypt content using a symmetric cipher.

       The passphrase is an str object (a unicode string)
       The plaintext is str() or bytes()
       The output is bytes()

       # encryption use
       >>> message = "texte avec caractères accentués"
       >>> c = encrypt(message, 'foobar')
       
    """
    # prépare les arguments à envoyer à openssl
    pass_arg = 'pass:{0}'.format(passphrase)
    args = ['openssl', 'enc', '-d', '-' + cipher, '-pass', pass_arg]
    
    # si le message clair est une chaine unicode, on est obligé de
    # l'encoder en bytes() pour pouvoir l'envoyer dans le pipeline vers 
    # openssl
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate(plaintext)

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    return stdout.decode()

def verify_certif(trusted, untrusted1, untrusted2):
    """invoke the OpenSSL library (though the openssl executable which must be
       present on your system) to encrypt content using a symmetric cipher.

       The passphrase is an str object (a unicode string)
       The plaintext is str() or bytes()
       The output is bytes()

       # encryption use
       >>> message = "texte avec caractères accentués"
       >>> c = encrypt(message, 'foobar')
       
    """
    # prépare les fichiers de certificat
    f = open('t1', 'w+')
    f.write(trusted)
    f.close()
    f = open('ut1', 'w+')
    f.write(untrusted1)
    f.close()
    f = open('ut2', 'w+')
    f.write(untrusted2)
    f.close()
    
    # prépare les arguments à envoyer à openssl
    args = ['openssl', 'verify', '-trusted', 't1', '-untrusted', 'ut1', 'ut2']

    # ouvre le pipeline vers openssl. Redirige stdin, stdout et stderr
    #    affiche la commande invoquée
    #    print('debug : {0}'.format(' '.join(args)))
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    # envoie plaintext sur le stdin de openssl, récupère stdout et stderr
    stdout, stderr = pipeline.communicate()

    # si un message d'erreur est présent sur stderr, on arrête tout
    # attention, sur stderr on récupère des bytes(), donc on convertit
    error_message = stderr.decode()
    if error_message != '':
        return ''

    # OK, openssl a envoyé le chiffré sur stdout, en base64.
    # On récupère des bytes, donc on en fait une chaine unicode
    out = stdout.decode()
    
    return out

def verify_challenge(challenge, certif, signature):
    f = open('challenge', 'w+')
    f.write(challenge)
    f.close()
    f = open('certif', 'w+')
    f.write(certif)
    f.close()
    f = open('signature', 'wb')
    f.write(base64.b64decode(signature))
    f.close()

    args = ['openssl', 'x509', '-pubkey', '-noout', '-in', 'certif']
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = pipeline.communicate()

    error_message = stderr.decode()
    if error_message != '':
       raise OpensslError(error_message)

    f = open('pubkey', 'w+')
    f.write(stdout.decode())
    f.close()

    args = ['openssl', 'dgst', '-sha256', '-verify', 'pubkey', '-signature', 'signature', 'challenge']
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = pipeline.communicate()

    error_message = stderr.decode()
    if error_message != '':
        return ''

    return stdout.decode()

def getText(certif):
    args = ['openssl', 'x509', '-noout', '-text']
    pipeline = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    
    if isinstance(certif, str):
        certif= certif.encode('utf-8')
    stdout, stderr = pipeline.communicate(certif)
    
    error_message = stderr.decode()
    if error_message != '':
        raise OpensslError(error_message)

    return stdout.decode()
