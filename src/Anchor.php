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
		'SECRET_KEY' => '_token',
		'SECRET' => '@nkor_leaf$0Secret!',
		'EXCEPT' => [],
		'METHODS' => ['POST', 'PUT', 'PATCH', 'DELETE'],
	];

	protected static $errors = [];

	/**
	 * Manage config for leaf anchor
	 * 
	 * @param array|null $config The config to set
	 */
	public static function config($config = null)
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
		} else {
			$data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
		}

		return $data;
	}

	/**
	 * Generate a token for identifying your application
	 * 
	 * @param int $strength Number of random characters to attach to token
	 */
	public static function generateToken(int $strength = 16): string
	{
		return bin2hex(static::$config['SECRET'] . '.' . random_bytes($strength));;
	}

	/**
	 * Return an item or items from an array of items or a default value
	 * 
	 * @param array $items An array of items
	 * @param string|array $items The item(s) to return
	 * @param mixed $default The default value to return if no item is found
	 */
	public static function findFromArrayWithDefault($data, $items, $default = null)
	{
		$output = [];

		if (is_array($items)) {
			foreach ($items as $dataItem) {
				$output[$dataItem] = $data[$dataItem] ?? null;
			}
		} else {
			$output = $data[$items] ?? null;
		}

		return $output ?? $default;
	}

	public static function errors(): array
	{
		return static::$errors;
	}
}
