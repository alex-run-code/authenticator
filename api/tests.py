from rest_framework.test import APIClient, APITestCase
from django.urls import reverse
from django.contrib.auth.models import User

# Create your tests here.

class AuthenticatorTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user("alextester", "alex@mail.com", "p4s$word")
        self.client = APIClient()
        self.login_url = reverse('login')
        self.helloworld_url = reverse('hello-world')
        self.extractor_url = reverse('extract-token')
        self.access_token = self.client.post(self.login_url,
         {'username': 'alextester', 'password':'p4s$word'}).json()['access']

    def test_login_return_jwt(self):
        """
        The login view return an access token and a refresh token
        """

        credentials = {
            'username': 'alextester',
            'password': 'p4s$word',
        }

        response = self.client.post(self.login_url, credentials)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('access' in response.json().keys())
        self.assertTrue('refresh' in response.json().keys())

    def test_bad_login_dont_return_jwt(self):
        """
        The login view doesnt return token if we use bad credentials
        """

        credentials = {
            'username': 'alextester',
            'password': 'p4s$wordFAKE',
        }

        response = self.client.post(self.login_url, credentials)
        self.assertEqual(response.status_code, 401)

    def test_run_return_helloworld(self):
        """ 
        The helloworld view return hello world
        """

        expected_response = {'message':'Hello Word'}
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        response = self.client.get(self.helloworld_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), expected_response)

    def test_extract_token_return_username_and_password(self):
        """ 
        The extract token view return the username and the password of the user
        """

        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        response = self.client.get(self.extractor_url)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('username' in response.json().keys())
        self.assertTrue('password' in response.json().keys())



