# Importando os módulos necessários para definir os modelos.
from django.db import models
from django.contrib.auth.models import AbstractUser

# Definindo o modelo User, que é uma extensão do modelo de usuário padrão fornecido pelo Django.
class User(AbstractUser):
    # Definindo campos adicionais que queremos para o nosso usuário.
    first_name = models.CharField(max_length=255)  # Primeiro nome do usuário.
    last_name = models.CharField(max_length=255)   # Último nome do usuário.
    email = models.CharField(max_length=255, unique=True)  # E-mail do usuário, que deve ser único.
    password = models.CharField(max_length=255)    # Senha do usuário.
    username = None    # Removendo o campo de nome de usuário padrão.

    USERNAME_FIELD = 'email'  # Definindo o campo de email como o campo de nome de usuário.
    REQUIRED_FIELDS = []  # Não exigindo nenhum campo adicional no momento do registro.

# Definindo o modelo UserToken para armazenar os tokens de atualização dos usuários.
class UserToken(models.Model):
    user_id = models.IntegerField()   # O id do usuário a que este token pertence.
    token = models.CharField(max_length=255)   # O token de atualização.
    created_at = models.DateField(auto_now_add=True)  # A data em que o token foi criado.
    expired_at = models.DateField()  # A data em que o token expira.

# Definindo o modelo Reset para gerenciar a recuperação de senha.
class Reset(models.Model):
    email = models.CharField(max_length=225)  # O email do usuário que solicita a redefinição de senha.
    token = models.CharField(max_length=225, unique=True)  # O token único que será usado para redefinir a senha.
