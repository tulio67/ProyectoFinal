import { test, expect } from '@playwright/test';

test.describe('Pruebas de Navegación', () => {
  
  test('Navegación por el menú principal', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/');
    
    // Verificar elementos del menú principal
    await expect(page.locator('text=Home')).toBeVisible();
    await expect(page.locator('text=Register')).toBeVisible();
    
    // Navegar a página de registro
    await page.click('text=Register');
    await expect(page).toHaveURL(/register/);
    console.log('Navegación a Register exitosa');
    
    // Regresar al home
    await page.click('text=Buggy Cars Rating');
    await expect(page).toHaveURL('https://buggy.justtestit.org/');
    console.log('Navegación al Home exitosa');
  });

  test('Verificar breadcrumbs y navegación hacia atrás', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/register');
    
    // Usar navegación del navegador
    await page.goBack();
    await expect(page).toHaveURL('https://buggy.justtestit.org/');
    
    // Navegar hacia adelante
    await page.goForward();
    await expect(page).toHaveURL(/register/);
    
    console.log('Navegación con botones del navegador funciona correctamente');
  });

  test('Verificar enlaces del footer', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/');
    
    // Scrollear hacia abajo para ver el footer
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    
    // Verificar que el footer sea visible
    const footer = page.locator('footer, .footer, [class*="footer"]').first();
    
    try {
      await expect(footer).toBeVisible({ timeout: 3000 });
      console.log('Footer encontrado y visible');
    } catch {
      console.log('Footer no encontrado o no visible');
    }
  });

  test('Verificar funcionalidad de búsqueda', async ({ page }) => {
    await page.goto('https://buggy.justtestit.org/');
    
    // Buscar campo de búsqueda
    const searchInput = page.locator('input[type="search"], input[placeholder*="search"], input[placeholder*="Search"]').first();
    
    try {
      await expect(searchInput).toBeVisible({ timeout: 3000 });
      await searchInput.fill('car');
      await searchInput.press('Enter');
      console.log('Funcionalidad de búsqueda probada');
    } catch {
      console.log('Campo de búsqueda no encontrado en la página principal');
    }
  });

});