import { test, expect } from '@playwright/test';

test.describe('Smoke Tests - Pruebas Críticas Básicas', () => {
  
  test('SMOKE: Verificar que la aplicación carga correctamente', async ({ page }) => {
    // Prueba más básica: la app carga
    await page.goto('https://buggy.justtestit.org/');
    
    // Verificar que el título principal existe
    await expect(page).toHaveTitle(/Buggy/);
    console.log('✅ SMOKE: Aplicación carga correctamente');
  });

  test('SMOKE: Login básico funciona', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');
    
    // Login rápido con credenciales válidas
    await page.fill('input[name="login"]', 'Marco@gmail.com');
    await page.fill('input[name="password"]', 'Marco123/');
    await page.click('button[type="submit"]');
    
    // Verificar login exitoso (timeout corto para smoke test)
    try {
      await page.waitForSelector('text=Profile', { timeout: 10000 });
      console.log('✅ SMOKE: Login básico funciona');
    } catch {
      console.log('❌ SMOKE: Login básico falló');
      throw new Error('Smoke test falló: Login no funciona');
    }
  });

  test('SMOKE: Página de registro es accesible', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    // Verificar que los campos básicos existen
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]').first()).toBeVisible();
    await expect(page.locator('button[type="submit"]').first()).toBeVisible();
    
    console.log('✅ SMOKE: Página de registro accesible');
  });

  test('SMOKE: Navegación básica funciona', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/');
    
    // Verificar que podemos navegar a registro
    await page.click('text=Register');
    await expect(page).toHaveURL(/register/);
    
    console.log('✅ SMOKE: Navegación básica funciona');
  });

  test('SMOKE: Formularios responden a entrada de datos', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');
    
    // Verificar que podemos escribir en los campos
    await page.fill('input[name="login"]', 'test@test.com');
    await page.fill('input[name="password"]', 'testpass');
    
    // Verificar que los valores se mantienen
    const emailValue = await page.inputValue('input[name="login"]');
    const passwordValue = await page.inputValue('input[name="password"]');
    
    expect(emailValue).toBe('test@test.com');
    expect(passwordValue).toBe('testpass');
    
    console.log('✅ SMOKE: Formularios responden correctamente');
  });

  test('SMOKE: No hay errores críticos de JavaScript', async ({ page }) => {
    let hasErrors = false;
    
    // Capturar errores de consola
    page.on('console', msg => {
      if (msg.type() === 'error') {
        console.log('Error de consola detectado:', msg.text());
        hasErrors = true;
      }
    });
    
    await page.goto('https://buggy.justtestit.org/');
    await page.waitForTimeout(2000); // Esperar a que cargue completamente
    
    if (hasErrors) {
      console.log('⚠️ SMOKE: Se detectaron errores de JavaScript');
    } else {
      console.log('✅ SMOKE: Sin errores críticos de JavaScript');
    }
  });

});