import { test, expect } from '@playwright/test';

test.describe('Pruebas de Validación de Formularios', () => {
  
  test('Validar formato de email en login', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/login');
    
    // Probar con email inválido
    await page.fill('input[name="login"]', 'email-invalido');
    await page.fill('input[name="password"]', 'cualquier-password');
    await page.click('button[type="submit"]');
    
    // Verificar que el campo de email tenga validación HTML5
    const emailField = page.locator('input[name="login"]');
    const emailType = await emailField.getAttribute('type');
    
    if (emailType === 'email') {
      console.log('Campo de login tiene validación de email HTML5');
    }
    
    console.log('Prueba de validación de email completada');
  });

  test('Validar longitud mínima de contraseña', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    const timestamp = Date.now();
    
    // Llenar formulario con contraseña muy corta
    await page.fill('input[name="username"]', `marco${timestamp}`);
    await page.fill('input[name="firstName"]', 'Marco');
    await page.fill('input[name="lastName"]', 'Tulio');
    await page.fill('input[name="password"]', '123'); // Contraseña muy corta
    await page.fill('input[name="confirmPassword"]', '123');
    
    await page.click('button[type="submit"]');
    
    // Verificar validaciones del lado del cliente
    const passwordField = page.locator('input[name="password"]');
    const minLength = await passwordField.getAttribute('minlength');
    
    if (minLength) {
      console.log(`Campo de contraseña tiene longitud mínima: ${minLength}`);
    }
    
    console.log('Prueba de longitud de contraseña completada');
  });

  test('Validar campos requeridos', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    // Verificar atributos required en campos
    const campos = [
      'input[name="username"]',
      'input[name="firstName"]', 
      'input[name="lastName"]',
      'input[name="password"]',
      'input[name="confirmPassword"]'
    ];
    
    for (const campo of campos) {
      const element = page.locator(campo);
      const isRequired = await element.getAttribute('required');
      
      if (isRequired !== null) {
        console.log(`Campo ${campo} es requerido`);
      }
    }
    
    console.log('Verificación de campos requeridos completada');
  });

  test('Probar caracteres especiales en formularios', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    const timestamp = Date.now();
    
    // Probar con caracteres especiales
    await page.fill('input[name="username"]', `marco_${timestamp}!@#`);
    await page.fill('input[name="firstName"]', 'Marco');
    await page.fill('input[name="lastName"]', 'Tulio-García');
    await page.fill('input[name="password"]', 'Marco123!@#');
    await page.fill('input[name="confirmPassword"]', 'Marco123!@#');
    
    await page.click('button[type="submit"]');
    
    // Esperar respuesta del servidor
    await page.waitForTimeout(2000);
    
    console.log('Prueba con caracteres especiales completada');
  });

});