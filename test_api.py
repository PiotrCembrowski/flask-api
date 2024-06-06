import requests

ENDPOINT = 'http://127.0.0.1:5000/files'

def test_can_call_endpoint():
    response = requests.get(ENDPOINT)
    assert response.status_code == 200
    
    
def text_can_create_file():
    payload = {
        "content": "My test content",
        "user_id": "test_user",
        "task_id": "test_file_id",
        "is_done": False
    }
    response = requests.post(ENDPOINT + '/files', json=payload)
    assert response.status_code == 200