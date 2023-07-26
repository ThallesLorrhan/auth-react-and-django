# Importa as bibliotecas necessárias.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import exceptions
from .serializers import *
from .authentication import *
from rest_framework.authentication import get_authorization_header
import random, string
from django.core.mail import send_mail

# Define a classe de View para o registro de usuários.
class RegisterAPIViews(APIView):
    # Define o método POST para essa view.
    def post(self, request):
        # Coleta os dados enviados na requisição.
        data = request.data

        # Verifica se a senha e a confirmação de senha são iguais.
        if data['password'] != data["password_confirm"]:
            raise exceptions.APIException('passwords do not match')
        
        # Cria um serializador com os dados recebidos.
        serializer = UserSerializers(data=data)
        # Verifica se os dados são válidos.
        serializer.is_valid(raise_exception=True)
        # Salva o usuário no banco de dados.
        serializer.save()

        # Retorna a resposta com os dados do usuário.
        return Response(serializer.data)

# Define a classe de View para o login de usuários.
class LoginAPIViews(APIView):
    # Define o método POST para essa view.
    def post(self, request):
        # Coleta o email e a senha enviados na requisição.
        email = request.data["email"]
        password = request.data["password"]
        # Busca o usuário correspondente ao email.
        user = User.objects.filter(email=email).first()

        # Se o usuário não for encontrado ou a senha estiver incorreta, levanta uma exceção.
        if user is None or not user.check_password(password):
            raise exceptions.AuthenticationFailed("Invalid credentials")
        
        # Cria os tokens de acesso e de atualização.
        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)

        # Salva o token de atualização no banco de dados.
        UserToken.objects.create(
            user_id=user.id,
            token=refresh_token,
            expired_at=datetime.datetime.utcnow() + datetime.timedelta(days=7),
        )

        # Configura o token de atualização como um cookie e retorna a resposta com o token de acesso.
        response = Response()
        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)
        response.data = {
            'token': access_token,
        }
        return response

# Define a classe de View para a obtenção de dados de usuário autenticado.
class UserAPIViews(APIView):
    # Define o tipo de autenticação necessário.
    authentication_classes = [JWTAuthentication]

    # Define o método GET para essa view.
    def get(self, request):
        # Retorna os dados do usuário autenticado.
        return Response(UserSerializers(request.user).data)

# Define a classe de View para a atualização do token de acesso.
class RefreshAPIViews(APIView):
    # Define o método POST para essa view.
    def post(self, request):
        # Coleta o token de atualização a partir dos cookies da requisição.
        refresh_token = request.COOKIES.get('refresh_token')
        # Decodifica o token de atualização para obter o id do usuário.
        id = decode_refresh_token(refresh_token)

        # Se o token de atualização não for encontrado ou já tiver expirado, levanta uma exceção.
        if not UserToken.objects.filter(
            user_id=id,
            token=refresh_token,
            expired_at__gt=datetime.datetime.now(tz=datetime.timezone.utc)
        ).exists():
            raise exceptions.AuthenticationFailed('unauthenticated')

        # Cria um novo token de acesso.
        access_token = create_access_token(id)

        # Retorna a resposta com o novo token de acesso.
        return Response({
            'token': access_token
        })

# Define a classe de View para o logout de usuários.
class LogoutAPIViews(APIView):
    # Define o tipo de autenticação necessário.
    authentication_classes = [JWTAuthentication]

    # Define o método POST para essa view.
    def post(self, request):
        # Coleta o token de atualização a partir dos cookies da requisição.
        refresh_token = request.COOKIES.get('refresh_token')

        # Deleta o token de atualização do banco de dados.
        UserToken.objects.filter(token=refresh_token).delete()

        # Configura a resposta para deletar o cookie do token de atualização.
        response = Response()
        response.delete_cookie(key='refresh_token')
        # Retorna uma resposta indicando sucesso.
        response.data = {
            'message': 'success'
        }

        return response

# Define a classe de View para a função de recuperação de senha.
class ForgotAPIView(APIView):
    # Define o método POST para essa view.
    def post(self, request):
        # Coleta o email da requisição.
        email = request.data['email']
        # Gera um token aleatório.
        token = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

        # Cria um registro de reset de senha no banco de dados.
        Reset.objects.create(
            email=email,
            token=token
        )

        # Envia um email ao usuário com o link para resetar a senha.
        url = 'http://localhost:3000/reset/' + token
        send_mail(
            subject='Reset your password!',
            message='Click <a href="%s">here</a> to reset your password!' % url,
            from_email='from@example.com',
            recipient_list=[email]
        )

        # Retorna uma resposta indicando sucesso.
        return Response({
            'message': 'success'
        })

# Define a classe de View para a função de reset de senha.
class ResetAPIViews(APIView):
    # Define o método POST para essa view.
    def post(self, request):
        # Coleta os dados da requisição.
        data = request.data

        # Verifica se a senha e a confirmação de senha são iguais.
        if data['password'] != data["password_confirm"]:
            raise exceptions.APIException('passwords do not match')

        # Busca o registro de reset de senha no banco de dados.
        reset_password = Reset.objects.filter(token=data['token']).first()

        # Se o registro de reset de senha não for encontrado, levanta uma exceção.
        if not reset_password:
            raise exceptions.APIException('Invalid Link')

        # Busca o usuário pelo email associado ao registro de reset de senha.
        user = User.objects.filter(email=reset_password.email).first()

        # Se o usuário não for encontrado, levanta uma exceção.
        if not user:
            raise exceptions.APIException('User not found')

        # Altera a senha do usuário e salva no banco de dados.
        user.set_password(data['password'])
        user.save()

        # Retorna uma resposta indicando sucesso.
        return Response({
            'message': 'success'
        })