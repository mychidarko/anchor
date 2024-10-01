<?php

declare(strict_types=1);

namespace Leaf;

/**
 * Leaf Security Module
 * ---------------------------------
 * Simple to use security based utility methods
 *
 * @author Michael Darko <mickdd22@gmail.com>
 * @since v2.2
 * @version 1.0
 */
class Anchor
{
	protected static $config = [
		'secret' => '@nkor_leaf$0Secret!!',
		'secretKey' => 'X-Leaf-CSRF-Token',

		'except' => [],
		'methods' => ['POST', 'PUT', 'PATCH', 'DELETE'],

		'messages.tokenNotFound' => 'Token not found.',
		'messages.tokenInvalid' => 'Invalid token.',

		'onError' => null,
	];

	protected static $modules = [
		'auth' => 'Leaf\Auth',
		'cookie' => 'Leaf\Http\Cookie',
		'csrf' => 'Leaf\Anchor\Csrf',
		'db' => 'Leaf\Db',
		'logger' => 'Leaf\Log',
		'session' => 'Leaf\Http\Session',
	];

	protected static $errors = [];

	/**
	 * Manage config for leaf anchor
	 *
	 * @param array|null $config The config to set
	 */
	public static function config(array $config = null)
	{
		if ($config === null) {
			return static::$config;
		}

		static::$config = array_merge(static::$config, $config);
	}

	/**
	 * Escape malicious characters
	 *
	 * @param mixed $data The data to sanitize.
	 */
	public static function sanitize($data)
	{
		if (is_array($data)) {
			foreach ($data as $key => $value) {
				$data[is_string($key) ? self::sanitize($key) : $key] = self::sanitize($value);
			}
		}

		if (is_string($data)) {
			$data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
		}

		return $data;
	}

	/**
	 * Check if a module is installed
   * 
   * @param string $moduleName The name of the module to check for
   * @return bool
	 */
	public static function checkModule(string $moduleName): bool
	{
		return class_exists(static::$modules[$moduleName]);
	}

  /**
   * Check if a module is installed/throw error
   * 
   * @param string $moduleName The name of the module to check for
   * @return bool
   */
  public static function checkModuleWithWarning(string $moduleName): bool
  {
    if (!static::checkModule($moduleName)) {
      header('Content-Type: text/html');
      trigger_error("Leaf $moduleName not found. Run `leaf install $moduleName` or `composer require leafs/$moduleName`");

      return false;
    }

    return true;
  }

	/**
	 * Get an item or items from an array of data.
	 * 
	 * @param array $dataSource An array of data to search through
	 * @param string|array $item The items to return
	 */
	public static function deepGet(array $dataSource, $item = null)
	{
		if (!$item) {
			return $dataSource;
		}

		$output = [];

		if (is_array($item)) {
			foreach ($item as $dataItem) {
				$output[$dataItem] = $dataSource[$dataItem] ?? null;
			}
		} else {
			$output = $dataSource[$item] ?? null;
		}

		return $output;
	}

    /**
     * Generate a token for identifying your application
     *
     * @param int $strength Number of random characters to attach to token
     * @throws \Exception
     */
	public static function generateToken(int $strength = 16): string
	{
		return bin2hex(static::$config['secret'] . '.' . random_bytes($strength));
	}

	public static function errors(): array
	{
		return static::$errors;
	}
}
