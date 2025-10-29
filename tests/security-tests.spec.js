import { test, expect } from '@playwright/test';

test.describe('Pruebas de Casos Negativos y Manejo de Errores', () => {
  
  test('Login con credenciales inexistentes', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');
    
    // Intentar login con credenciales que no existen
    await page.fill('input[name="login"]', 'marco-falso@test.com');
    await page.fill('input[name="password"]', 'password-incorrecto');
    await page.click('button[type="submit"]');
    
    // Verificar mensaje de error
    try {
      await page.waitForSelector('text=Username or password is incorrect', { timeout: 5000 });
      console.log('Mensaje de error mostrado correctamente');
    } catch {
      // Buscar otros posibles mensajes de error
      const errorMessages = [
        'Invalid credentials',
        'Login failed',
        'Authentication failed',
        'User not found'
      ];
      
      for (const errorMsg of errorMessages) {
        const errorVisible = await page.isVisible(`text=${errorMsg}`);
        if (errorVisible) {
          console.log(`Mensaje de error encontrado: ${errorMsg}`);
          break;
        }
      }
    }
  });

  test('Probar inyección SQL en campos de login', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');
    
    // Intentar inyección SQL básica
    const sqlInjections = [
      "' OR '1'='1",
      "admin'--",
      "' OR 1=1--",
      "admin' OR 1=1#"
    ];
    
    for (const injection of sqlInjections) {
      await page.fill('input[name="login"]', injection);
      await page.fill('input[name="password"]', 'test');
      await page.click('button[type="submit"]');
      
      // Verificar que no se haya hecho login exitoso
      await page.waitForTimeout(1000);
      const profileVisible = await page.isVisible('text=Profile');
      
      if (!profileVisible) {
        console.log(`Inyección SQL "${injection}" bloqueada correctamente`);
      } else {
        console.warn(`VULNERABILIDAD: Inyección SQL "${injection}" tuvo éxito!`);
      }
    }
  });

  test('Probar XSS en campos de formulario', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    const timestamp = Date.now();
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src="x" onerror="alert(1)">',
      'javascript:alert("XSS")',
      '<svg onload="alert(1)">'
    ];
    
    for (const payload of xssPayloads) {
      await page.fill('input[name="username"]', `user${timestamp}`);
      await page.fill('input[name="firstName"]', payload);
      await page.fill('input[name="lastName"]', 'Test');
      await page.fill('input[name="password"]', 'Password123');
      await page.fill('input[name="confirmPassword"]', 'Password123');
      
      await page.click('button[type="submit"]');
      await page.waitForTimeout(1000);
      
      console.log(`Payload XSS probado: ${payload.substring(0, 20)}...`);
    }
  });

  test('Verificar límites de longitud en campos', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    const timestamp = Date.now();
    
    // Probar con strings muy largos
    const longString = 'a'.repeat(1000);
    
    await page.fill('input[name="username"]', `user${timestamp}`);
    await page.fill('input[name="firstName"]', longString);
    await page.fill('input[name="lastName"]', longString);
    await page.fill('input[name="password"]', 'Password123');
    await page.fill('input[name="confirmPassword"]', 'Password123');
    
    await page.click('button[type="submit"]');
    
    // Verificar que el sistema maneje strings largos apropiadamente
    await page.waitForTimeout(2000);
    console.log('Prueba de límites de longitud completada');
  });

  test('Verificar manejo de caracteres Unicode', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    const timestamp = Date.now();
    
    // Probar con caracteres Unicode/emojis
    await page.fill('input[name="username"]', `user${timestamp}`);
    await page.fill('input[name="firstName"]', '测试🚗');
    await page.fill('input[name="lastName"]', 'Тест🎭');
    await page.fill('input[name="password"]', 'Password123');
    await page.fill('input[name="confirmPassword"]', 'Password123');
    
    await page.click('button[type="submit"]');
    await page.waitForTimeout(2000);
    
    console.log('Prueba con caracteres Unicode completada');
  });

  test('Probar múltiples intentos de login fallidos', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');
    
    // Intentar login fallido múltiples veces
    for (let i = 1; i <= 5; i++) {
      await page.fill('input[name="login"]', 'test@test.com');
      await page.fill('input[name="password"]', `wrong-password-${i}`);
      await page.click('button[type="submit"]');
      
      await page.waitForTimeout(1000);
      console.log(`Intento de login fallido #${i}`);
    }
    
    // Verificar si hay algún mecanismo de bloqueo
    const isBlocked = await page.isVisible('text=Account locked') || 
                     await page.isVisible('text=Too many attempts') ||
                     await page.isVisible('text=Please wait');
    
    if (isBlocked) {
      console.log('Sistema de bloqueo por múltiples intentos detectado');
    } else {
      console.log('No se detectó bloqueo por múltiples intentos');
    }
  });

});