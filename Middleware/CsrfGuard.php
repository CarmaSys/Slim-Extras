<?php
/**
 * CSRF Guard
 *
 * Use this middleware with your Slim Framework application
 * to protect you from CSRF attacks.
 *
 * USAGE
 *
 * $app = new \Slim\Slim();
 * $app->add(new \Slim\Extras\Middleware\CsrfGuard());
 *
 */
namespace Slim\Extras\Middleware;

class CsrfGuard extends \Slim\Middleware
{
    /**
     * CSRF token key name.
     *
     * @var string
     */
    protected $key;

    /**
     * Use cookie for CSRF token.
     *
     * @var bool
     */
    protected $useCookie = false;

    /**
     * Constructor.
     *
     * @param string    $key        The CSRF token key name.
     * @param bool      $cookie     Use a cookie to store CSRF token.
     * @return void
     */
    public function __construct($key = 'csrf_token', $cookie = false)
    {
        if (! is_string($key) || empty($key) || preg_match('/[^a-zA-Z0-9\-\_]/', $key)) {
            throw new \OutOfBoundsException('Invalid CSRF token key "' . $key . '"');
        }

        $this->key = $key;
        $this->useCookie = $cookie;
    }

    /**
     * Call middleware.
     *
     * @return void
     */
    public function call() 
    {
        // Attach as hook.
        $this->app->hook('slim.before', array($this, 'check'));

        // Call next middleware.
        $this->next->call();
    }

    /**
     * Generate CSRF Token.
     *
     * @return string
     */
    private static function generateToken() {
        return sha1(serialize($_SERVER) . rand(0, 0xffffffff));
    }

    /**
     * Get the current CSRF token according to session or cookie storage.
     *
     * @return string|false
     */
    protected function getToken() {
        if($this->useCookie && $this->app->getCookie($this->key)) {
            return $this->app->getCookie($this->key);            
        } else if(!$this->useCookie && isset($_SESSION[$this->key])) {
            return $_SESSION[$this->key];
        }
        return false;
    }

    /**
     * Set the current CSRF token according to session or cookie storage.
     * @param string    $token      CSRF token.
     * @return void
     */
    protected function setToken($token) {
        $this->useCookie ? $this->app->setCookie($this->key,$token) : $_SESSION[$this->key] = $token;
    }


    /**
     * Check CSRF token is valid.
     * Note: Also checks POST data to see if a Moneris RVAR CSRF token exists.
     *
     * @return void
     */
    public function check() {
        // Check sessions are enabled.
        if (!$this->useCookie && session_id() === '') {
            throw new \Exception('Sessions are required to use the CSRF Guard middleware.');
        }

        if(!$this->getToken()) {
            $token = self::generateToken();
            $this->setToken($token);
        } else {
            $token = $this->getToken();    
        }

        // Validate the CSRF token.
        if (in_array($this->app->request()->getMethod(), array('POST', 'PUT', 'DELETE'))) {
            // Check headers for X-XSRF-TOKEN to support AngularJS
            if($this->app->request()->isAjax() && $this->app->request()->headers('X-'.$this->key)) {
                $userToken = $this->app->request()->headers('X-' . $this->key);
            } else {
                $userToken = $this->app->request()->post($this->key);
            }
            if ($token !== $userToken) {
                $this->app->halt(400, 'Invalid or missing CSRF token.');
            }
        }

        // Assign CSRF token key and value to view.
        $this->app->view()->appendData(array(
            'csrf_key'      => $this->key,
            'csrf_token'    => $token,
        ));
    }
}