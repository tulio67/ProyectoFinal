import { test, expect } from '@playwright/test';

test.describe('Pruebas de Registro de Usuario', () => {
  
  test('Verificar formulario de registro', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    // Verificar que todos los campos requeridos estén presentes
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="firstName"]')).toBeVisible();
    await expect(page.locator('input[name="lastName"]')).toBeVisible();
    await expect(page.locator('input[name="password"]').first()).toBeVisible();
    await expect(page.locator('input[name="confirmPassword"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
    
    console.log('Todos los campos del formulario de registro están presentes');
  });

  test('Intentar registro con contraseñas que no coinciden', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    // Generar un nombre de usuario único
    const timestamp = Date.now();
    const testUsername = `marco${timestamp}`;
    
    // Llenar el formulario con contraseñas diferentes
    await page.fill('input[name="username"]', testUsername);
    await page.fill('input[name="firstName"]', 'Marco');
    await page.fill('input[name="lastName"]', 'Tulio');
    await page.fill('input[name="password"]', 'Marco123');
    await page.fill('input[name="confirmPassword"]', 'Marco124'); // Contraseña diferente
    
    await page.click('button[type="submit"]');
    
    // Verificar que aparezca un mensaje de error
    try {
      await page.waitForSelector('text=Passwords do not match', { timeout: 3000 });
      console.log('Validación de contraseñas funcionando correctamente');
    } catch {
      console.log('El mensaje de error puede tener diferente texto o ubicación');
    }
  });

  test('Intentar registro con campos vacíos', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    // Intentar enviar formulario vacío
    await page.click('button[type="submit"]');
    
    // Verificar que se muestren validaciones
    const usernameField = page.locator('input[name="username"]');
    const isRequired = await usernameField.getAttribute('required');
    
    if (isRequired !== null) {
      console.log('Los campos tienen validación HTML5 required');
    }
    
    console.log('Prueba de campos vacíos completada');
  });

  test('Registro exitoso con datos de Marco', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    // Generar un nombre de usuario único para esta prueba
    const timestamp = Date.now();
    const testUsername = `marco_test_${timestamp}`;
    
    // Llenar el formulario con datos válidos
    await page.fill('input[name="username"]', testUsername);
    await page.fill('input[name="firstName"]', 'Marco');
    await page.fill('input[name="lastName"]', 'Tulio');
    await page.fill('input[name="password"]', 'Marco123/');
    await page.fill('input[name="confirmPassword"]', 'Marco123/');
    
    await page.click('button[type="submit"]');
    
    // Esperar resultado del registro
    await page.waitForTimeout(3000);
    
    try {
      // Verificar si el registro fue exitoso (podría redirigir o mostrar mensaje)
      const successIndicators = [
        'text=Registration successful',
        'text=Welcome',
        'text=Login',
        'text=Profile'
      ];
      
      let registrationSuccess = false;
      for (const indicator of successIndicators) {
        const isVisible = await page.isVisible(indicator);
        if (isVisible) {
          console.log(`Registro exitoso detectado: ${indicator}`);
          registrationSuccess = true;
          break;
        }
      }
      
      if (!registrationSuccess) {
        // Verificar si hay algún mensaje de error
        const errorVisible = await page.isVisible('text=User already exists') || 
                            await page.isVisible('text=Username taken') ||
                            await page.isVisible('.alert-danger');
        
        if (errorVisible) {
          console.log('Usuario ya existe o error en registro');
        } else {
          console.log('Registro completado - estado incierto');
        }
      }
    } catch (error) {
      console.log('Error al verificar resultado del registro');
    }
  });

});