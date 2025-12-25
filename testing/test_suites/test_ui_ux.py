"""
UI/UX Tests - Test user interface and user experience
Note: Requires selenium or playwright for browser automation
"""
import pytest
import json
import time

# Check if selenium is available
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

PRODUCTION_URL = "https://antilanguageencryptiontool-y9rjc.ondigitalocean.app"

@pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not installed")
class TestUIKeyGeneration:
    """UI tests for key generation"""
    
    @pytest.fixture(scope="class")
    def driver(self):
        """Setup Chrome driver"""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Chrome(options=options)
        yield driver
        driver.quit()
    
    def test_keygen_ui_elements(self, driver):
        """Test that keygen UI elements are present"""
        driver.get(PRODUCTION_URL)
        
        # Wait for page to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        # Check for keygen tab
        keygen_tab = driver.find_element(By.XPATH, "//button[contains(text(), 'Generate Keys')]")
        assert keygen_tab is not None
    
    def test_keygen_form_interaction(self, driver):
        """Test keygen form interaction"""
        driver.get(PRODUCTION_URL)
        time.sleep(2)
        
        # Find and fill name field
        name_input = driver.find_element(By.ID, "keygen-name")
        name_input.clear()
        name_input.send_keys("UITestUser")
        
        # Find and click generate button
        generate_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Generate Keys')]")
        generate_button.click()
        
        # Wait for result
        time.sleep(3)
        
        # Check for result
        result_div = driver.find_element(By.ID, "keygen-result")
        assert result_div is not None
        assert "Keys Generated" in result_div.text or "Error" in result_div.text

@pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not installed")
class TestUIEncryption:
    """UI tests for encryption"""
    
    @pytest.fixture(scope="class")
    def driver(self):
        """Setup Chrome driver"""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Chrome(options=options)
        yield driver
        driver.quit()
    
    def test_encrypt_tab_switching(self, driver):
        """Test switching to encrypt tab"""
        driver.get(PRODUCTION_URL)
        time.sleep(2)
        
        # Click encrypt tab
        encrypt_tab = driver.find_element(By.XPATH, "//button[contains(text(), 'Encrypt')]")
        encrypt_tab.click()
        time.sleep(1)
        
        # Check encrypt form is visible
        encrypt_form = driver.find_element(By.ID, "encrypt")
        assert encrypt_form.is_displayed()

@pytest.mark.skipif(not SELENIUM_AVAILABLE, reason="Selenium not installed")
class TestUIResponsive:
    """Test responsive design"""
    
    @pytest.fixture(scope="class")
    def driver(self):
        """Setup Chrome driver"""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Chrome(options=options)
        yield driver
        driver.quit()
    
    def test_mobile_viewport(self, driver):
        """Test mobile viewport"""
        driver.set_window_size(375, 667)  # iPhone size
        driver.get(PRODUCTION_URL)
        time.sleep(2)
        
        # Check page loads
        body = driver.find_element(By.TAG_NAME, "body")
        assert body is not None
    
    def test_tablet_viewport(self, driver):
        """Test tablet viewport"""
        driver.set_window_size(768, 1024)  # iPad size
        driver.get(PRODUCTION_URL)
        time.sleep(2)
        
        body = driver.find_element(By.TAG_NAME, "body")
        assert body is not None

class TestUIFunctional:
    """Functional UI tests using API (no browser needed)"""
    
    def test_embed_page_accessible(self):
        """Test embed page is accessible"""
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(f"{PRODUCTION_URL}/embed", timeout=10, verify=False)
        assert response.status_code == 200
    
    def test_main_page_accessible(self):
        """Test main page is accessible"""
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get(PRODUCTION_URL, timeout=10, verify=False)
        assert response.status_code == 200
    
    def test_page_contains_expected_elements(self):
        """Test page contains expected HTML elements"""
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            pytest.skip("beautifulsoup4 not installed")
        
        response = requests.get(PRODUCTION_URL, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for key elements
        assert soup.find('title') is not None
        assert 'Forgotten-E2EE' in response.text

