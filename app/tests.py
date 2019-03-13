# python imports
import json
import time

# djnago imports
from django.contrib.auth.models import User
from django.test import Client
from django.test import TestCase

# User defined imports
from app.models import FeedActivity

# Create your tests here.
class HomePageTests(TestCase):
    def setUp(self):
        # Run testcase :
        # Ref: https://developer.mozilla.org/en-US/docs/Learn/Server-side/Django/Testing#Running_specific_tests
        # It will run every time once testcase has been started
        self.client = Client()
        self.user = User.objects.get_or_create(username='dummy',
                                              email='dummy@gmail.com',
                                              password='dummypass')[0]
        self.client.force_login(user=self.user, backend="django.contrib.auth.backends.ModelBackend")

    def tearDown(self):
        # It will run this once if testcase has ended
        for obj in [FeedActivity, User]:
            obj.objects.all().delete()

    def test_home_opening_test(self):
        response = self.client.get(path='/', follow=True) # follow will follow next url if it has any redirected url
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'home.html')

    def create_feed(self, desc='test_desc'):
        feed_url = '/fileupload/?action=create&desc=%s'%(desc)
        response = self.client.get(path=feed_url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), 'OK')
        feed_obj = FeedActivity.objects.filter(description__icontains=desc)
        self.assertEqual(feed_obj.exists(), True)
        return response, feed_obj.first().slug


    def test_create_feed_post(self):
        desc = 'create_feed'
        response, slug = self.create_feed(desc=desc)

    def test_like_for_feed_post(self):
        desc = 'create_feed'
        response, slug = self.create_feed(desc=desc)
        get_likes = lambda slug : FeedActivity.objects.get(slug=slug).likes_count
        self.assertEqual(get_likes(slug), 0)
        feed_data = {'feed_id':slug ,
                     'action':'like'}
        url = '/activity/'
        response = self.client.post(path=url,
                                    data=json.dumps(feed_data),
                                    content_type="application/json")
        self.assertEqual(response.json().get('success',''), True)
        self.assertEqual(get_likes(slug), 1)







