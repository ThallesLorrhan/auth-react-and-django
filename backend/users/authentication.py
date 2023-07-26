# Importando as bibliotecas necessárias
import jwt, datetime
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from .models import User

# Esta é a classe de autenticação personalizada. Ela herda de BaseAuthentication, um módulo fornecido pelo Django Rest Framework.
class JWTAuthentication(BaseAuthentication):
    # Esta função 'authenticate' é chamada para cada solicitação HTTP que requer autenticação.
    def authenticate(self, request):
        # Esta linha obtém o cabeçalho de autorização da solicitação e o divide em partes.
        auth = get_authorization_header(request).split()

        # Se o cabeçalho de autorização está presente e tem dois elementos (deve ser 'Bearer' e o token)
        if auth and len(auth) == 2:
            # Decodifica o token para utf-8 e obtém o id do usuário do token
            token = auth[1].decode('utf-8')
            id = decode_access_token(token)

            # Obtem o usuário correspondente ao id no banco de dados
            user = User.objects.get(pk=id)

            # Retorna o usuário e nenhum token de autenticação adicional
            return (user, None)

        # Se não for possível autenticar, uma exceção é lançada
        raise exceptions.AuthenticationFailed('unauthenticated')

# Esta função cria um token de acesso com base no id do usuário. O token expira após 30 segundos.
def create_access_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        'iat': datetime.datetime.utcnow()
    }, 'access_secret', algorithm='HS256')

# Esta função tenta decodificar um token de acesso fornecido e retornar o id do usuário.
# Se não for possível decodificar o token, uma exceção é lançada.
def decode_access_token(token):
    try:
        payload = jwt.decode(token, 'access_secret', algorithms='HS256')
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('unauthenticated')

# Esta função cria um token de atualização com base no id do usuário. O token expira após 7 dias.
def create_refresh_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }, 'refresh_secret', algorithm='HS256')

# Esta função tenta decodificar um token de atualização fornecido e retornar o id do usuário.
# Se não for possível decodificar o token, uma exceção é lançada.
def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms='HS256')
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('unauthenticated')
