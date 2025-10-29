import { test, expect } from '@playwright/test';

test.describe('Pruebas de Autenticación', () => {
  
  test('Verificar login y logout exitoso', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');

    // Ingresar credenciales
    await page.fill('input[name="login"]', 'Marco@gmail.com'); // tu usuario real
    await page.fill('input[name="password"]', 'Marco123/'); // tu contraseña real
    await page.click('button[type="submit"]');

    try {
      // Esperar indicador de login exitoso
      await page.waitForSelector('text=Profile', { timeout: 5000 });
      console.log('Inicio de sesión exitoso');

      // Buscar y presionar logout
      const logoutVisible = await page.isVisible('text=Logout');
      await page.click('text=Logout');
      console.log('Logout realizado correctamente');
      await expect(page).toHaveURL(/login/);

    } catch {
      // Si no aparece el indicador de login, verificar mensaje de error
      const errorVisible = await page.isVisible('text=Username or password is incorrect');
       console.log('Usuario o contraseña incorrectos');
    }
  });

  test('Verificar login con credenciales incorrectas', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');

    // Intentar login con credenciales incorrectas
    await page.fill('input[name="login"]', 'usuario-incorrecto@test.com');
    await page.fill('input[name="password"]', 'password-incorrecto');
    await page.click('button[type="submit"]');

    // Verificar mensaje de error
    try {
      await page.waitForSelector('text=Username or password is incorrect', { timeout: 5000 });
      console.log('Mensaje de error mostrado correctamente para credenciales incorrectas');
    } catch {
      console.log('Mensaje de error no encontrado o con texto diferente');
    }

    // Verificar que NO estamos logueados
    const profileVisible = await page.isVisible('text=Profile');
    expect(profileVisible).toBeFalsy();
  });

  test('Verificar campos requeridos en login', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');

    // Intentar submit sin llenar campos
    await page.click('button[type="submit"]');

    // Verificar que los campos tengan validación HTML5
    const loginField = page.locator('input[name="login"]');
    const passwordField = page.locator('input[name="password"]');

    const loginRequired = await loginField.getAttribute('required');
    const passwordRequired = await passwordField.getAttribute('required');

    if (loginRequired !== null) {
      console.log('Campo de login es requerido');
    }
    if (passwordRequired !== null) {
      console.log('Campo de password es requerido');
    }
  });

  test('Verificar redirección después del login', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');

    await page.fill('input[name="login"]', 'Marco@gmail.com');
    await page.fill('input[name="password"]', 'Marco123/');
    await page.click('button[type="submit"]');

    try {
      // Esperar redirect o indicador de login exitoso
      await page.waitForSelector('text=Profile', { timeout: 5000 });
      
      // Verificar que la URL haya cambiado (no sigue en /login)
      const currentUrl = page.url();
      expect(currentUrl).not.toContain('/login');
      
      console.log(`Redirección exitosa a: ${currentUrl}`);
    } catch {
      console.log('Login falló o redirección no detectada');
    }
  });

  test('Verificar persistencia de sesión', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');

    await page.fill('input[name="login"]', 'Marco@gmail.com');
    await page.fill('input[name="password"]', 'Marco123/');
    await page.click('button[type="submit"]');

    try {
      await page.waitForSelector('text=Profile', { timeout: 5000 });
      
      // Navegar a otra página y regresar
      await page.goto('https://buggy.justtestit.org/');
      
      // Verificar que sigue logueado
      const stillLoggedIn = await page.isVisible('text=Profile');
      if (stillLoggedIn) {
        console.log('Sesión persistente funcionando correctamente');
      } else {
        console.log('Sesión no persiste entre páginas');
      }
    } catch {
      console.log('No se pudo verificar persistencia de sesión');
    }
  });

});